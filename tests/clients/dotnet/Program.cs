// Compatibility checks for Microsoft.Data.SqlClient through the TDS proxy.
//
// usage:
//   dotnet run -- suite "<connection string>"
//   dotnet run -- expect-login-failure "<connection string>"
//   dotnet run -- whoami "<connection string>"
using System.Data;
using System.Diagnostics;
using System.Reflection;
using Microsoft.Data.SqlClient;

if (args.Length < 2)
{
    Console.Error.WriteLine("usage: <suite|expect-login-failure|whoami> <connection string>");
    return 2;
}
var mode = args[0];
var cs = args[1];
var driver = typeof(SqlConnection).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
Console.WriteLine($"Microsoft.Data.SqlClient {driver} on .NET {Environment.Version}");

switch (mode)
{
    case "expect-login-failure":
        try
        {
            using var c = new SqlConnection(cs);
            c.Open();
            Console.WriteLine("FAIL: login unexpectedly succeeded");
            return 1;
        }
        catch (SqlException e)
        {
            Console.WriteLine($"PASS: login rejected: error {e.Number}: {e.Message}");
            return 0;
        }
    case "whoami":
        using (var c = new SqlConnection(cs))
        {
            c.Open();
            Console.WriteLine(Scalar(c, "SELECT SUSER_SNAME()"));
        }
        return 0;
}

var failed = 0;
void Check(string name, Action body)
{
    var sw = Stopwatch.StartNew();
    try
    {
        body();
        Console.WriteLine($"PASS  {name} ({sw.ElapsedMilliseconds} ms)");
    }
    catch (Exception e)
    {
        failed++;
        Console.WriteLine($"FAIL  {name}: {e.GetType().Name}: {e.Message}");
    }
}
void Assert(bool cond, string msg) { if (!cond) throw new Exception(msg); }

using var conn = new SqlConnection(cs);
Check("open", conn.Open);
Console.WriteLine($"      server version {conn.ServerVersion}, packet size {conn.PacketSize}, spid {conn.ServerProcessId}");

Check("SELECT 1", () => Assert(Convert.ToInt32(Scalar(conn, "SELECT 1")) == 1, "expected 1"));
Check("SELECT @@VERSION", () => Assert(((string)Scalar(conn, "SELECT @@VERSION")).Contains("SQL Server"), "unexpected version"));
Check("SELECT DB_NAME()", () => Console.WriteLine($"      DB_NAME() = {Scalar(conn, "SELECT DB_NAME()")}"));
Check("SELECT SUSER_SNAME()", () => Console.WriteLine($"      SUSER_SNAME() = {Scalar(conn, "SELECT SUSER_SNAME()")}"));
Check("@@SPID matches header SPID", () => Assert(Convert.ToInt32(Scalar(conn, "SELECT @@SPID")) == conn.ServerProcessId, "SPID mismatch"));

Check("temporary table", () =>
{
    Exec(conn, "CREATE TABLE #ProxyTest (Id INT)");
    Exec(conn, "INSERT INTO #ProxyTest VALUES (1)");
    Assert(Convert.ToInt32(Scalar(conn, "SELECT * FROM #ProxyTest")) == 1, "temp table row");
    Exec(conn, "DROP TABLE #ProxyTest");
});

Check("transaction commit", () =>
{
    Exec(conn, "CREATE TABLE #Tx (Id INT)");
    using (var tx = conn.BeginTransaction())
    {
        using var cmd = new SqlCommand("INSERT INTO #Tx VALUES (1); SELECT 1;", conn, tx);
        cmd.ExecuteScalar();
        tx.Commit();
    }
    Assert(Convert.ToInt32(Scalar(conn, "SELECT COUNT(*) FROM #Tx")) == 1, "committed row missing");
});

Check("transaction rollback", () =>
{
    using (var tx = conn.BeginTransaction())
    {
        using var cmd = new SqlCommand("INSERT INTO #Tx VALUES (2)", conn, tx);
        cmd.ExecuteNonQuery();
        tx.Rollback();
    }
    Assert(Convert.ToInt32(Scalar(conn, "SELECT COUNT(*) FROM #Tx")) == 1, "rolled back row present");
});

Check("parameterized query (RPC sp_executesql)", () =>
{
    using var cmd = new SqlCommand("SELECT @a + @b, @s", conn);
    cmd.Parameters.Add("@a", SqlDbType.Int).Value = 40;
    cmd.Parameters.Add("@b", SqlDbType.Int).Value = 2;
    cmd.Parameters.Add("@s", SqlDbType.NVarChar, 50).Value = "héllo ✓";
    using var r = cmd.ExecuteReader();
    Assert(r.Read(), "no row");
    Assert(r.GetInt32(0) == 42 && r.GetString(1) == "héllo ✓", "wrong values");
});

Check("stored procedure with output parameter", () =>
{
    Exec(conn, "CREATE OR ALTER PROCEDURE #AddOne @x INT, @y INT OUTPUT AS BEGIN SET @y = @x + 1; SELECT 'rs' AS c; END");
    using var cmd = new SqlCommand("#AddOne", conn) { CommandType = CommandType.StoredProcedure };
    cmd.Parameters.Add("@x", SqlDbType.Int).Value = 41;
    var y = cmd.Parameters.Add("@y", SqlDbType.Int);
    y.Direction = ParameterDirection.Output;
    using (var r = cmd.ExecuteReader()) { while (r.Read()) { } }
    Assert((int)y.Value == 42, "output parameter");
});

Check("multiple result sets", () =>
{
    using var cmd = new SqlCommand("SELECT 1; SELECT 2, 3; SELECT 'x'", conn);
    using var r = cmd.ExecuteReader();
    var sets = 0;
    do { while (r.Read()) { } sets++; } while (r.NextResult());
    Assert(sets == 3, $"expected 3 result sets, got {sets}");
});

Check("large result set (200k rows, ~40 MB)", () =>
{
    using var cmd = new SqlCommand(
        "SELECT TOP (200000) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS n, REPLICATE(N'x', 100) AS pad " +
        "FROM sys.all_objects a CROSS JOIN sys.all_objects b", conn) { CommandTimeout = 120 };
    using var r = cmd.ExecuteReader();
    long rows = 0, sum = 0;
    while (r.Read()) { rows++; sum += r.GetInt64(0); }
    Assert(rows == 200000 && sum == 200000L * 200001 / 2, $"rows={rows}");
});

Check("large parameter (2 MB nvarchar(max))", () =>
{
    var big = new string('y', 1_000_000);
    using var cmd = new SqlCommand("SELECT LEN(@p)", conn);
    cmd.Parameters.Add("@p", SqlDbType.NVarChar, -1).Value = big;
    Assert(Convert.ToInt32(cmd.ExecuteScalar()) == big.Length, "length mismatch");
});

Check("server error is relayed", () =>
{
    try { Exec(conn, "SELECT 1/0"); throw new Exception("no error raised"); }
    catch (SqlException e) { Assert(e.Number == 8134, $"unexpected error {e.Number}"); }
    Assert(Convert.ToInt32(Scalar(conn, "SELECT 1")) == 1, "connection unusable after error");
});

Check("query cancellation (attention)", () =>
{
    using var cmd = new SqlCommand("WAITFOR DELAY '00:00:30'", conn);
    var t = Task.Run(() => { try { cmd.ExecuteNonQuery(); return (Exception?)null; } catch (Exception e) { return e; } });
    Thread.Sleep(1000);
    var sw = Stopwatch.StartNew();
    cmd.Cancel();
    var e = t.Result;
    Assert(e is SqlException, $"expected SqlException, got {e?.GetType().Name ?? "none"}");
    Assert(sw.ElapsedMilliseconds < 10000, "cancel took too long");
    Assert(Convert.ToInt32(Scalar(conn, "SELECT 1")) == 1, "connection unusable after cancel");
});

Check("command timeout (attention)", () =>
{
    using var cmd = new SqlCommand("WAITFOR DELAY '00:00:20'", conn) { CommandTimeout = 2 };
    try { cmd.ExecuteNonQuery(); throw new Exception("no timeout"); }
    catch (SqlException e) { Assert(e.Number == -2, $"unexpected error {e.Number}"); }
    Assert(Convert.ToInt32(Scalar(conn, "SELECT 1")) == 1, "connection unusable after timeout");
});

Check("pooled connection reset (sp_reset_connection)", () =>
{
    var pooled = new SqlConnectionStringBuilder(cs) { Pooling = true, ApplicationName = "proxy-pool-test" }.ConnectionString;
    int spid1, spid2;
    using (var c = new SqlConnection(pooled)) { c.Open(); Exec(c, "CREATE TABLE #Pool (i INT)"); spid1 = c.ServerProcessId; }
    using (var c = new SqlConnection(pooled))
    {
        c.Open();
        spid2 = c.ServerProcessId;
        Assert(Convert.ToInt32(Scalar(c, "SELECT CASE WHEN OBJECT_ID('tempdb..#Pool') IS NULL THEN 1 ELSE 0 END")) == 1, "session not reset");
    }
    Assert(spid1 == spid2, "connection was not reused from pool");
});

Check("concurrent connections (20)", () =>
{
    var ncs = new SqlConnectionStringBuilder(cs) { Pooling = false }.ConnectionString;
    var tasks = Enumerable.Range(0, 20).Select(i => Task.Run(() =>
    {
        using var c = new SqlConnection(ncs);
        c.Open();
        return Convert.ToInt32(Scalar(c, $"SELECT {i}"));
    })).ToArray();
    Task.WaitAll(tasks);
    Assert(tasks.Select(t => t.Result).OrderBy(x => x).SequenceEqual(Enumerable.Range(0, 20)), "wrong results");
});

Check("MARS (two concurrent readers)", () =>
{
    var mcs = new SqlConnectionStringBuilder(cs) { MultipleActiveResultSets = true, Pooling = false }.ConnectionString;
    using var c = new SqlConnection(mcs);
    c.Open();
    using var c1 = new SqlCommand("SELECT TOP 1000 object_id FROM sys.all_objects", c);
    using var r1 = c1.ExecuteReader();
    var n = 0;
    while (r1.Read())
    {
        if (n++ % 200 == 0)
            Assert(Convert.ToInt32(Scalar(c, "SELECT 7")) == 7, "inner query");
    }
    Assert(n > 0, "no rows");
});

Console.WriteLine(failed == 0 ? "ALL PASSED" : $"{failed} FAILED");
return failed == 0 ? 0 : 1;

static object Scalar(SqlConnection c, string sql)
{
    using var cmd = new SqlCommand(sql, c);
    return cmd.ExecuteScalar()!;
}
static void Exec(SqlConnection c, string sql)
{
    using var cmd = new SqlCommand(sql, c);
    cmd.ExecuteNonQuery();
}
