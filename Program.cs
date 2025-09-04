using System;
using System.IO;
using System.Text;
using System.Text.Json;

class Program
{
	static void PrintAuthor()
	{
		Console.WriteLine("t.me/Bengamin_Button t.me/XillenAdapter");
	}

	static void Usage()
	{
		PrintAuthor();
		Console.WriteLine("usage: dotnet run [--from rules.json] [--out sysmon.xml]");
		Console.WriteLine("rules.json example: { \"hashes\": true, \"imageLoads\": true, \"dns\": false }");
	}

	class Rules
	{
		public bool hashes { get; set; } = true;
		public bool imageLoads { get; set; } = true;
		public bool processCreate { get; set; } = true;
		public bool networkConnect { get; set; } = true;
		public bool dns { get; set; } = true;
	}

	static string BuildXml(Rules r)
	{
		var sb = new StringBuilder();
		sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
		sb.AppendLine("<Sysmon schemaversion=\"4.30\">");
		sb.AppendLine("  <HashAlgorithms>md5,sha256</HashAlgorithms>");
		sb.AppendLine("  <EventFiltering>");
		if (r.processCreate) sb.AppendLine("    <ProcessCreate onmatch=\"include\"><Rule groupRelation=\"or\"><CommandLine condition=\"contains\">*</CommandLine></Rule></ProcessCreate>");
		if (r.imageLoads) sb.AppendLine("    <ImageLoad onmatch=\"include\"><Rule groupRelation=\"or\"><ImageLoaded condition=\"end with\">.dll</ImageLoaded></Rule></ImageLoad>");
		if (r.networkConnect) sb.AppendLine("    <NetworkConnect onmatch=\"include\"><Rule groupRelation=\"or\"><DestinationPort condition=\"is\">443</DestinationPort></Rule></NetworkConnect>");
		if (r.dns) sb.AppendLine("    <DnsQuery onmatch=\"include\"><Rule groupRelation=\"or\"><QueryName condition=\"contains\">.</QueryName></Rule></DnsQuery>");
		sb.AppendLine("  </EventFiltering>");
		sb.AppendLine("</Sysmon>");
		return sb.ToString();
	}

	static int Main(string[] args)
	{
		PrintAuthor();
		string? rulesPath = null;
		string outPath = "sysmon.xml";
		for (int i = 0; i < args.Length; i++)
		{
			if (args[i] == "--from" && i + 1 < args.Length) { rulesPath = args[++i]; continue; }
			if (args[i] == "--out" && i + 1 < args.Length) { outPath = args[++i]; continue; }
		}

		Rules rules = new Rules();
		if (rulesPath != null && File.Exists(rulesPath))
		{
			try
			{
				var text = File.ReadAllText(rulesPath);
				rules = JsonSerializer.Deserialize<Rules>(text) ?? new Rules();
			}
			catch (Exception)
			{
				Console.Error.WriteLine("Failed to parse rules.json, using defaults");
			}
		}

		var xml = BuildXml(rules);
		File.WriteAllText(outPath, xml, new UTF8Encoding(false));
		Console.WriteLine(outPath);
		return 0;
	}
}
