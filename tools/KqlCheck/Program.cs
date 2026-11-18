// Offline check for the KQL hunting queries in kql/.
//
// Parses every query with Microsoft's own KQL parser and semantic analyser (Kusto.Language) against a
// schema of the Defender XDR and Sentinel tables (kql/schema/tables.json). That catches syntax errors,
// unknown tables, misspelt columns and type errors without a Microsoft tenant. It cannot prove that a
// query returns the right rows; that needs real data.
//
// Every query must also start with a "// Purpose:" comment, so the runbook can link to it.
// Queries in kql/tests/invalid/ are known to be wrong and must fail, which proves the checker works.
//
//   dotnet run --project tools/KqlCheck -- kql

using System.Text;
using System.Text.Json;
using Kusto.Language;
using Kusto.Language.Symbols;

var root = args.Length > 0 ? args[0] : "kql";
if (!Directory.Exists(root))
{
    Console.Error.WriteLine($"Folder not found: {root}");
    return 2;
}

GlobalState globals;
try
{
    globals = SchemaLoader.Load(Path.Combine(root, "schema", "tables.json"));
}
catch (Exception ex) when (ex is IOException or JsonException or InvalidDataException)
{
    Console.Error.WriteLine($"Schema could not be loaded: {ex.Message}");
    return 2;
}

var failed = 0;
var queries = Directory.GetFiles(root, "*.kql").Order(StringComparer.Ordinal).ToArray();
if (queries.Length == 0)
{
    Console.Error.WriteLine($"No .kql files in {root}");
    return 2;
}

foreach (var file in queries)
{
    var text = File.ReadAllText(file);
    var problems = QueryChecker.Errors(text, globals).ToList();
    if (!text.TrimStart().StartsWith("// Purpose:", StringComparison.Ordinal))
    {
        problems.Insert(0, "1:1 the query must start with a '// Purpose:' comment");
    }

    if (problems.Count == 0)
    {
        Console.WriteLine($"OK    {Path.GetFileName(file)}");
        continue;
    }

    failed++;
    foreach (var problem in problems)
    {
        Console.WriteLine($"FAIL  {Path.GetFileName(file)}:{problem}");
    }
}

var invalidFolder = Path.Combine(root, "tests", "invalid");
string[] invalidFiles = Directory.Exists(invalidFolder) ? Directory.GetFiles(invalidFolder, "*.kql") : [];
foreach (var file in invalidFiles.Order(StringComparer.Ordinal))
{
    var errors = QueryChecker.Errors(File.ReadAllText(file), globals).ToList();
    if (errors.Count == 0)
    {
        failed++;
        Console.WriteLine($"FAIL  tests/invalid/{Path.GetFileName(file)} was accepted, but it is known to be wrong");
    }
    else
    {
        Console.WriteLine($"OK    tests/invalid/{Path.GetFileName(file)} rejected: {errors[0]}");
    }
}

Console.WriteLine(failed == 0 ? "All KQL checks passed." : $"{failed} KQL file(s) failed.");
return failed == 0 ? 0 : 1;

static class QueryChecker
{
    public static IEnumerable<string> Errors(string text, GlobalState globals)
    {
        var code = KustoCode.ParseAndAnalyze(text, globals);
        foreach (var diagnostic in code.GetDiagnostics())
        {
            if (diagnostic.Severity != DiagnosticSeverity.Error)
            {
                continue;
            }

            var (line, column) = Position(text, diagnostic.Start);
            yield return $"{line}:{column} {diagnostic.Message}";
        }
    }

    private static (int Line, int Column) Position(string text, int offset)
    {
        int line = 1, column = 1;
        for (var i = 0; i < Math.Min(offset, text.Length); i++)
        {
            if (text[i] == '\n')
            {
                line++;
                column = 1;
            }
            else
            {
                column++;
            }
        }

        return (line, column);
    }
}

static class SchemaLoader
{
    // tables.json: { "tables": { "EmailEvents": { "docs": "<url>", "columns": { "Timestamp": "datetime", ... } } } }
    public static GlobalState Load(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var tables = new List<Symbol>();
        foreach (var table in document.RootElement.GetProperty("tables").EnumerateObject())
        {
            var schema = new StringBuilder("(");
            var first = true;
            foreach (var column in table.Value.GetProperty("columns").EnumerateObject())
            {
                schema.Append(first ? "" : ", ").Append(column.Name).Append(':').Append(column.Value.GetString());
                first = false;
            }

            if (first)
            {
                throw new InvalidDataException($"table {table.Name} has no columns");
            }

            tables.Add(new TableSymbol(table.Name, schema.Append(')').ToString()));
        }

        return GlobalState.Default.WithDatabase(new DatabaseSymbol("hunting", tables));
    }
}
