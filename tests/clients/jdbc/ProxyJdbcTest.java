// JDBC (mssql-jdbc, the driver DBeaver uses) compatibility checks through the proxy.
// Run with tests/clients/jdbc/run.sh.
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;

public class ProxyJdbcTest {
    static int failed = 0;

    interface Body { void run() throws Exception; }

    static void check(String name, Body b) {
        long t = System.nanoTime();
        try {
            b.run();
            System.out.printf("PASS  %s (%d ms)%n", name, (System.nanoTime() - t) / 1_000_000);
        } catch (Throwable e) {
            failed++;
            System.out.printf("FAIL  %s: %s%n", name, e);
        }
    }

    static void ok(boolean c, String m) { if (!c) throw new AssertionError(m); }

    static Object scalar(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement(); ResultSet r = s.executeQuery(sql)) { r.next(); return r.getObject(1); }
    }

    public static void main(String[] a) throws Exception {
        String url = a[0];
        if (a.length > 1 && a[1].equals("expect-login-failure")) {
            try (Connection c = DriverManager.getConnection(url)) {
                System.out.println("FAIL: login unexpectedly succeeded"); System.exit(1);
            } catch (SQLException e) {
                System.out.println("PASS: login rejected: error " + e.getErrorCode() + ": " + e.getMessage()); return;
            }
        }
        Connection c = DriverManager.getConnection(url);
        DatabaseMetaData md = c.getMetaData();
        System.out.println(md.getDriverName() + " " + md.getDriverVersion() + " / Java " + System.getProperty("java.version"));

        check("SELECT 1", () -> ok(((Number) scalar(c, "SELECT 1")).intValue() == 1, "1"));
        check("SELECT @@VERSION", () -> ok(scalar(c, "SELECT @@VERSION").toString().contains("SQL Server"), "version"));
        check("SELECT DB_NAME()", () -> System.out.println("      DB_NAME() = " + scalar(c, "SELECT DB_NAME()")));
        check("SELECT SUSER_SNAME()", () -> System.out.println("      SUSER_SNAME() = " + scalar(c, "SELECT SUSER_SNAME()")));
        check("temporary table", () -> {
            try (Statement s = c.createStatement()) {
                s.execute("CREATE TABLE #ProxyTest (Id INT)");
                s.execute("INSERT INTO #ProxyTest VALUES (1)");
                ok(((Number) scalar(c, "SELECT * FROM #ProxyTest")).intValue() == 1, "row");
                s.execute("DROP TABLE #ProxyTest");
            }
        });
        check("transaction commit/rollback", () -> {
            try (Statement s = c.createStatement()) {
                s.execute("CREATE TABLE #Tx (Id INT)");
                c.setAutoCommit(false);
                s.execute("INSERT INTO #Tx VALUES (1)");
                c.commit();
                s.execute("INSERT INTO #Tx VALUES (2)");
                c.rollback();
                c.setAutoCommit(true);
                ok(((Number) scalar(c, "SELECT COUNT(*) FROM #Tx")).intValue() == 1, "count");
            }
        });
        check("prepared statement (RPC)", () -> {
            try (PreparedStatement p = c.prepareStatement("SELECT ? + ?, ?")) {
                p.setInt(1, 40); p.setInt(2, 2); p.setNString(3, "héllo ✓");
                try (ResultSet r = p.executeQuery()) {
                    r.next(); ok(r.getInt(1) == 42 && r.getString(2).equals("héllo ✓"), "values");
                }
            }
        });
        check("stored procedure (CallableStatement)", () -> {
            try (Statement s = c.createStatement()) {
                s.execute("CREATE PROCEDURE #AddOne @x INT, @y INT OUTPUT AS SET @y = @x + 1");
            }
            try (CallableStatement cs = c.prepareCall("{call #AddOne(?, ?)}")) {
                cs.setInt(1, 41); cs.registerOutParameter(2, Types.INTEGER); cs.execute();
                ok(cs.getInt(2) == 42, "out param");
            }
        });
        check("multiple result sets", () -> {
            try (Statement s = c.createStatement()) {
                boolean rs = s.execute("SELECT 1; SELECT 2; SELECT 3");
                int n = 0;
                while (rs || s.getUpdateCount() != -1) {
                    if (rs) { try (ResultSet r = s.getResultSet()) { while (r.next()) n += r.getInt(1); } }
                    rs = s.getMoreResults();
                }
                ok(n == 6, "sum " + n);
            }
        });
        check("large result set (200k rows)", () -> {
            try (Statement s = c.createStatement(); ResultSet r = s.executeQuery(
                "SELECT TOP (200000) CAST(ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS BIGINT), REPLICATE(N'x', 100) " +
                "FROM sys.all_objects a CROSS JOIN sys.all_objects b")) {
                long n = 0, sum = 0;
                while (r.next()) { n++; sum += r.getLong(1); }
                ok(n == 200000 && sum == 200000L * 200001 / 2, "rows " + n);
            }
        });
        check("server error relayed", () -> {
            // mssql-jdbc surfaces errors in a result stream when it is read.
            try (Statement s = c.createStatement(); ResultSet r = s.executeQuery("SELECT 1/0")) { r.next(); throw new AssertionError("no error"); }
            catch (SQLException e) { ok(e.getErrorCode() == 8134, "error " + e.getErrorCode()); }
        });
        check("query cancellation (attention)", () -> {
            try (Statement s = c.createStatement()) {
                ExecutorService ex = Executors.newSingleThreadExecutor();
                Future<?> f = ex.submit(() -> { try { s.execute("WAITFOR DELAY '00:00:30'"); } catch (SQLException e) { return e; } return null; });
                Thread.sleep(1000);
                long t0 = System.nanoTime();
                s.cancel();
                Object r = f.get(10, TimeUnit.SECONDS);
                ex.shutdown();
                ok(r instanceof SQLException, "expected cancel exception, got " + r);
                ok((System.nanoTime() - t0) < 10_000_000_000L, "slow cancel");
            }
            ok(((Number) scalar(c, "SELECT 1")).intValue() == 1, "connection usable after cancel");
        });
        check("query timeout", () -> {
            try (Statement s = c.createStatement()) {
                s.setQueryTimeout(2);
                try { s.execute("WAITFOR DELAY '00:00:20'"); throw new AssertionError("no timeout"); } catch (SQLTimeoutException e) { }
            }
            ok(((Number) scalar(c, "SELECT 1")).intValue() == 1, "connection usable after timeout");
        });
        check("concurrent connections (20)", () -> {
            ExecutorService ex = Executors.newFixedThreadPool(20);
            List<Future<Integer>> fs = new ArrayList<>();
            for (int i = 0; i < 20; i++) { final int v = i; fs.add(ex.submit(() -> {
                try (Connection cc = DriverManager.getConnection(url)) { return ((Number) scalar(cc, "SELECT " + v)).intValue(); } })); }
            int sum = 0; for (Future<Integer> f : fs) sum += f.get(60, TimeUnit.SECONDS);
            ex.shutdown();
            ok(sum == 190, "sum " + sum);
        });
        check("DBeaver-style metadata queries", () -> {
            DatabaseMetaData m = c.getMetaData();
            try (ResultSet r = m.getCatalogs()) { int n = 0; while (r.next()) n++; ok(n > 0, "catalogs"); }
            try (ResultSet r = m.getTables("master", "sys", "%", null)) { r.next(); }
            ok(m.getDatabaseProductVersion() != null, "product version");
        });
        c.close();
        System.out.println(failed == 0 ? "ALL PASSED" : failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
