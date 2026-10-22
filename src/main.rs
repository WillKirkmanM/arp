use clap::{Parser, Subcommand};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::fs;
use std::io::{self, Write as _};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

#[derive(Parser)]
#[command(
    name = "arp",
    version,
    about = "Inspect, look up and compare saved Windows ARP reports."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Group mappings by interface and flag conflicting MAC addresses.")]
    Inspect {
        #[arg(help = "Saved Windows arp -a report")]
        report: PathBuf,
    },
    #[command(about = "Find mappings for an IPv4 address.")]
    Lookup {
        #[arg(help = "Saved Windows arp -a report")]
        report: PathBuf,
        #[arg(help = "IPv4 address to look up")]
        address: Ipv4Addr,
        #[arg(
            short = 'i',
            long,
            value_name = "INDEX",
            value_parser = parse_interface_index,
            help = "Restrict matches to a decimal or hexadecimal interface index"
        )]
        interface: Option<u32>,
    },
    #[command(about = "Compare mappings by interface index and IPv4 address.")]
    Compare {
        #[arg(help = "Earlier saved Windows arp -a report")]
        before: PathBuf,
        #[arg(help = "Later saved Windows arp -a report")]
        after: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MacAddress([u8; 6]);

impl FromStr for MacAddress {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || {
            format!(
                "invalid MAC address '{value}'; expected six two-digit hexadecimal octets separated by '-' or ':'"
            )
        };
        if value.len() != 17 || !value.is_ascii() {
            return Err(invalid());
        }
        let separator = match value.as_bytes()[2] {
            b'-' => '-',
            b':' => ':',
            _ => return Err(invalid()),
        };
        let mut octets = [0; 6];
        let mut parts = value.split(separator);
        for octet in &mut octets {
            let part = parts.next().ok_or_else(invalid)?;
            if part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(invalid());
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| invalid())?;
        }
        if parts.next().is_some() {
            return Err(invalid());
        }
        Ok(Self(octets))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(formatter, "{a:02x}-{b:02x}-{c:02x}-{d:02x}-{e:02x}-{f:02x}")
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum EntryType {
    Dynamic,
    Static,
}

impl fmt::Display for EntryType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Dynamic => "dynamic",
            Self::Static => "static",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Mapping {
    mac: MacAddress,
    kind: EntryType,
}

#[derive(Debug)]
struct Interface {
    address: Ipv4Addr,
    entries: BTreeMap<Ipv4Addr, BTreeSet<Mapping>>,
}

#[derive(Debug, Default)]
struct Report {
    interfaces: BTreeMap<u32, Interface>,
}

#[derive(Debug)]
struct RowError {
    line: usize,
    message: String,
}

fn parse_interface_index(value: &str) -> Result<u32, String> {
    let hexadecimal = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    let (digits, radix) = hexadecimal.map_or((value, 10), |digits| (digits, 16));
    if !digits.is_empty()
        && digits.bytes().all(|byte| match radix {
            16 => byte.is_ascii_hexdigit(),
            _ => byte.is_ascii_digit(),
        })
        && let Ok(index) = u32::from_str_radix(digits, radix)
    {
        return Ok(index);
    }
    Err(format!(
        "invalid interface index '{value}'; expected a 32-bit unsigned decimal number or hexadecimal value prefixed with 0x"
    ))
}

fn parse_header(fields: &[&str]) -> Result<(Ipv4Addr, u32), String> {
    if fields.len() != 4 || fields[2] != "---" {
        return Err("expected 'Interface: <IPv4 address> --- <hexadecimal index>'".into());
    }
    let address = fields[1]
        .parse()
        .map_err(|_| format!("invalid interface IPv4 address '{}'", fields[1]))?;
    if !fields[3].starts_with("0x") && !fields[3].starts_with("0X") {
        return Err(format!(
            "invalid interface index '{}'; expected a hexadecimal value prefixed with 0x",
            fields[3]
        ));
    }
    Ok((address, parse_interface_index(fields[3])?))
}

fn parse_entry(fields: &[&str]) -> Result<(Ipv4Addr, Mapping), String> {
    if fields.len() != 3 {
        return Err(
            "expected an IPv4 address, a MAC address and a dynamic or static entry type".into(),
        );
    }
    let address = fields[0]
        .parse()
        .map_err(|_| format!("invalid IPv4 address '{}'", fields[0]))?;
    let mac = fields[1].parse()?;
    let kind = if fields[2].eq_ignore_ascii_case("dynamic") {
        EntryType::Dynamic
    } else if fields[2].eq_ignore_ascii_case("static") {
        EntryType::Static
    } else {
        return Err(format!(
            "invalid entry type '{}'; expected dynamic or static",
            fields[2]
        ));
    };
    Ok((address, Mapping { mac, kind }))
}

fn parse_report(text: &str) -> Result<Report, Vec<RowError>> {
    let mut report = Report::default();
    let mut current = None;
    let mut recognised = false;
    let mut errors = Vec::new();
    for (position, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = position + 1;
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if raw.eq_ignore_ascii_case("No ARP Entries Found.") {
            recognised = true;
            continue;
        }
        let fields: Vec<_> = raw.split_whitespace().collect();
        let result = if fields[0].eq_ignore_ascii_case("Interface:") {
            current = None;
            parse_header(&fields).and_then(|(address, index)| {
                let interface = report.interfaces.entry(index).or_insert_with(|| Interface {
                    address,
                    entries: BTreeMap::new(),
                });
                if interface.address != address {
                    return Err(format!(
                        "interface index 0x{index:x} has conflicting interface addresses {} and {address}",
                        interface.address
                    ));
                }
                current = Some(index);
                recognised = true;
                Ok(())
            })
        } else if fields.len() == 5
            && fields
                .iter()
                .zip(["Internet", "Address", "Physical", "Address", "Type"])
                .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
        {
            current
                .map(|_| ())
                .ok_or_else(|| "table header appears before an interface".into())
        } else if let Some(index) = current {
            parse_entry(&fields).map(|(address, mapping)| {
                report
                    .interfaces
                    .get_mut(&index)
                    .unwrap()
                    .entries
                    .entry(address)
                    .or_default()
                    .insert(mapping);
            })
        } else {
            Err("expected an interface header before a mapping".into())
        };
        if let Err(message) = result {
            errors.push(RowError { line, message });
        }
    }
    if !recognised && errors.is_empty() {
        errors.push(RowError {
            line: 1,
            message: "report contains no interface headers or 'No ARP Entries Found.' message"
                .into(),
        });
    }
    if errors.is_empty() {
        Ok(report)
    } else {
        Err(errors)
    }
}

fn decode_report(bytes: &[u8]) -> Result<String, String> {
    let little_endian = bytes.starts_with(&[0xff, 0xfe]);
    if little_endian || bytes.starts_with(&[0xfe, 0xff]) {
        if !bytes.len().is_multiple_of(2) {
            return Err("report has an incomplete UTF-16 code unit".into());
        }
        let units: Vec<_> = bytes[2..]
            .chunks_exact(2)
            .map(|pair| {
                if little_endian {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            })
            .collect();
        String::from_utf16(&units).map_err(|_| "report is not valid UTF-16".into())
    } else {
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|error| {
                format!(
                    "report is not valid UTF-8 at byte {}",
                    error.valid_up_to() + 1
                )
            })
    }
}

fn read_report(path: &Path) -> Result<Report, String> {
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let text = decode_report(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    parse_report(&text).map_err(|errors| {
        errors
            .iter()
            .map(|error| format!("{}: line {}: {}", path.display(), error.line, error.message))
            .collect::<Vec<_>>()
            .join("\n")
    })
}

fn write_interface(output: &mut String, index: u32, interface: &Interface) {
    writeln!(output, "Interface: {} --- 0x{index:x}", interface.address).unwrap();
}

fn write_mappings(output: &mut String, address: Ipv4Addr, mappings: &BTreeSet<Mapping>) {
    for mapping in mappings {
        writeln!(output, "  {address}  {}  {}", mapping.mac, mapping.kind).unwrap();
    }
}

fn inspect(report: &Report) -> String {
    let mut output = String::new();
    for (&index, interface) in &report.interfaces {
        write_interface(&mut output, index, interface);
        let mut dynamic = 0;
        let mut static_entries = 0;
        for (&address, mappings) in &interface.entries {
            write_mappings(&mut output, address, mappings);
            let mut macs = BTreeSet::new();
            for mapping in mappings {
                match mapping.kind {
                    EntryType::Dynamic => dynamic += 1,
                    EntryType::Static => static_entries += 1,
                }
                macs.insert(mapping.mac);
            }
            if macs.len() > 1 {
                let macs = macs.iter().map(ToString::to_string).collect::<Vec<_>>();
                writeln!(output, "  Conflict: {address} -> {}", macs.join(", ")).unwrap();
            }
        }
        writeln!(
            output,
            "  Summary: {dynamic} dynamic, {static_entries} static, {} distinct IPv4 addresses",
            interface.entries.len()
        )
        .unwrap();
    }
    if output.is_empty() {
        output.push_str("No mappings found.\n");
    }
    output
}

fn lookup(report: &Report, address: Ipv4Addr, index: Option<u32>) -> Result<String, String> {
    let mut output = String::new();
    for (&interface_index, interface) in &report.interfaces {
        if index.is_some_and(|index| index != interface_index) {
            continue;
        }
        if let Some(mappings) = interface.entries.get(&address) {
            write_interface(&mut output, interface_index, interface);
            write_mappings(&mut output, address, mappings);
        }
    }
    if output.is_empty() {
        let scope = index.map_or_else(String::new, |index| format!(" on interface 0x{index:x}"));
        Err(format!("no mappings found for {address}{scope}"))
    } else {
        Ok(output)
    }
}

fn describe_mappings(mappings: &BTreeSet<Mapping>) -> String {
    mappings
        .iter()
        .map(|mapping| format!("{} ({})", mapping.mac, mapping.kind))
        .collect::<Vec<_>>()
        .join(", ")
}

fn compare(before: &Report, after: &Report) -> String {
    let keys: BTreeSet<_> = [before, after]
        .into_iter()
        .flat_map(|report| {
            report.interfaces.iter().flat_map(|(&index, interface)| {
                interface
                    .entries
                    .keys()
                    .map(move |&address| (index, address))
            })
        })
        .collect();
    let mut output = String::new();
    let mut added = 0;
    let mut removed = 0;
    let mut changed = 0;
    for (index, address) in keys {
        let mappings = |report: &Report| {
            report
                .interfaces
                .get(&index)
                .and_then(|interface| interface.entries.get(&address))
                .cloned()
                .unwrap_or_default()
        };
        let old = mappings(before);
        let new = mappings(after);
        if old == new {
            continue;
        }
        let scope = format!("interface 0x{index:x}, {address}");
        if old.is_empty() {
            added += 1;
            writeln!(output, "Added: {scope} -> {}", describe_mappings(&new)).unwrap();
        } else if new.is_empty() {
            removed += 1;
            writeln!(output, "Removed: {scope} -> {}", describe_mappings(&old)).unwrap();
        } else {
            changed += 1;
            writeln!(
                output,
                "Changed: {scope}: {} -> {}",
                describe_mappings(&old),
                describe_mappings(&new)
            )
            .unwrap();
        }
    }
    if output.is_empty() {
        output.push_str("No differences found.\n");
    } else {
        writeln!(
            output,
            "Summary: {added} added, {removed} removed, {changed} changed"
        )
        .unwrap();
    }
    output
}

fn run(command: Command) -> Result<String, String> {
    match command {
        Command::Inspect { report } => Ok(inspect(&read_report(&report)?)),
        Command::Lookup {
            report,
            address,
            interface,
        } => lookup(&read_report(&report)?, address, interface),
        Command::Compare { before, after } => {
            Ok(compare(&read_report(&before)?, &read_report(&after)?))
        }
    }
}

fn main() -> ExitCode {
    let result = run(Cli::parse().command).and_then(|output| {
        io::stdout()
            .lock()
            .write_all(output.as_bytes())
            .map_err(|error| format!("cannot write output: {error}"))
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_macs_and_counts_distinct_mappings() {
        let report = parse_report(
            "\u{feff}Interface: 192.168.1.10 --- 0x6\r\n\
               Internet Address Physical Address Type\r\n\
               192.168.1.20 02:AA:BB:CC:DD:02 STATIC\r\n\
               192.168.1.1 02-AA-BB-CC-DD-01 dynamic\r\n\
               192.168.1.1 02-aa-bb-cc-dd-01 dynamic\r\n",
        )
        .unwrap();
        assert_eq!(
            inspect(&report),
            concat!(
                "Interface: 192.168.1.10 --- 0x6\n",
                "  192.168.1.1  02-aa-bb-cc-dd-01  dynamic\n",
                "  192.168.1.20  02-aa-bb-cc-dd-02  static\n",
                "  Summary: 1 dynamic, 1 static, 2 distinct IPv4 addresses\n"
            )
        );
    }

    #[test]
    fn reports_invalid_rows_with_their_line_numbers() {
        let errors = parse_report(
            "Interface: 192.168.1.10 --- 0x6\n\
             Internet Address Physical Address Type\n\
             192.168.1.999 02-aa-bb-cc-dd-01 dynamic\n\
             192.168.1.1 02-aa-bb:cc-dd-01 dynamic\n\
             192.168.1.2 02-aa-bb-cc-dd-02 permanent\n",
        )
        .unwrap_err();
        assert_eq!(
            errors.iter().map(|error| error.line).collect::<Vec<_>>(),
            [3, 4, 5]
        );
        assert!(errors[0].message.contains("invalid IPv4 address"));
        assert!(errors[1].message.contains("invalid MAC address"));
        assert!(errors[2].message.contains("invalid entry type"));
    }

    #[test]
    fn flags_conflicts_only_within_each_interface() {
        let report = parse_report(
            "Interface: 10.0.0.10 --- 0xc\n\
             10.0.0.1 02-aa-bb-cc-ee-03 dynamic\n\
             Interface: 192.168.1.10 --- 0x6\n\
             10.0.0.1 02-aa-bb-cc-ee-02 static\n\
             10.0.0.1 02-aa-bb-cc-ee-01 dynamic\n\
             10.0.0.2 02-aa-bb-cc-ee-04 static\n\
             10.0.0.2 02-aa-bb-cc-ee-04 dynamic\n",
        )
        .unwrap();
        let output = inspect(&report);
        assert_eq!(output.matches("Conflict:").count(), 1);
        assert!(output.contains("Conflict: 10.0.0.1 -> 02-aa-bb-cc-ee-01, 02-aa-bb-cc-ee-02"));
        assert!(output.find("0x6").unwrap() < output.find("0xc").unwrap());
    }

    #[test]
    fn restricts_lookup_to_the_requested_interface() {
        let report = parse_report(
            "Interface: 10.0.0.10 --- 0xc\n\
             10.0.0.1 02-aa-bb-cc-ee-01 dynamic\n\
             Interface: 192.168.1.10 --- 0x6\n\
             10.0.0.1 02-aa-bb-cc-ee-02 static\n",
        )
        .unwrap();
        let address = "10.0.0.1".parse().unwrap();
        assert_eq!(
            lookup(&report, address, None)
                .unwrap()
                .matches("Interface:")
                .count(),
            2
        );
        let output = lookup(&report, address, Some(12)).unwrap();
        assert!(output.contains("02-aa-bb-cc-ee-01"));
        assert!(!output.contains("02-aa-bb-cc-ee-02"));
        assert!(lookup(&report, address, Some(7)).is_err());
        assert!(lookup(&report, "10.0.0.2".parse().unwrap(), None).is_err());
    }

    #[test]
    fn compares_mac_and_type_changes_by_index_and_address() {
        let before = parse_report(
            "Interface: 192.168.1.10 --- 0x6\n\
             192.168.1.1 02-aa-bb-cc-dd-01 dynamic\n\
             192.168.1.2 02-aa-bb-cc-dd-02 dynamic\n\
             192.168.1.3 02-aa-bb-cc-dd-03 static\n\
             Interface: 10.0.0.10 --- 0xc\n\
             192.168.1.5 02-aa-bb-cc-dd-05 dynamic\n",
        )
        .unwrap();
        let after = parse_report(
            "Interface: 192.168.1.11 --- 0x6\n\
             192.168.1.1 02-aa-bb-cc-dd-11 dynamic\n\
             192.168.1.2 02-aa-bb-cc-dd-02 static\n\
             192.168.1.4 02-aa-bb-cc-dd-04 dynamic\n\
             192.168.1.5 02-aa-bb-cc-dd-05 dynamic\n",
        )
        .unwrap();
        let output = compare(&before, &after);
        assert!(output.contains("Changed: interface 0x6, 192.168.1.1: 02-aa-bb-cc-dd-01 (dynamic) -> 02-aa-bb-cc-dd-11 (dynamic)"));
        assert!(output.contains("Changed: interface 0x6, 192.168.1.2: 02-aa-bb-cc-dd-02 (dynamic) -> 02-aa-bb-cc-dd-02 (static)"));
        assert!(output.contains("Removed: interface 0x6, 192.168.1.3"));
        assert!(output.contains("Added: interface 0x6, 192.168.1.4"));
        assert!(output.contains("Added: interface 0x6, 192.168.1.5"));
        assert!(output.contains("Removed: interface 0xc, 192.168.1.5"));
        assert!(output.ends_with("Summary: 2 added, 2 removed, 2 changed\n"));
    }

    #[test]
    fn ignores_mapping_order_and_exact_duplicates_in_comparisons() {
        let before = parse_report(
            "Interface: 10.0.0.10 --- 0x6\n\
             10.0.0.1 02-AA-BB-CC-DD-01 dynamic\n\
             10.0.0.1 02-aa-bb-cc-dd-02 static\n",
        )
        .unwrap();
        let after = parse_report(
            "Interface: 10.0.0.20 --- 0x6\n\
             10.0.0.1 02-aa-bb-cc-dd-02 static\n\
             10.0.0.1 02:aa:bb:cc:dd:01 dynamic\n\
             10.0.0.1 02-aa-bb-cc-dd-02 static\n",
        )
        .unwrap();
        assert_eq!(compare(&before, &after), "No differences found.\n");
    }

    #[test]
    fn validates_headers_indices_and_missing_interfaces() {
        for text in [
            "",
            "Internet Address Physical Address Type",
            "10.0.0.1 02-aa-bb-cc-dd-01 dynamic",
            "Interface: 10.0.0.999 --- 0x6",
            "Interface: 10.0.0.10 --- 6",
            "Interface: 10.0.0.10 --- 0x100000000",
            "Interface: 10.0.0.10 --- 0x6\nInterface: 10.0.0.11 --- 0x6",
        ] {
            assert!(
                parse_report(text).is_err(),
                "accepted invalid report: {text}"
            );
        }
        assert_eq!(parse_interface_index("12").unwrap(), 12);
        assert_eq!(parse_interface_index("0xC").unwrap(), 12);
        for value in ["", "-1", "+6", "0x", "0x+6", "4294967296"] {
            assert!(parse_interface_index(value).is_err());
        }
    }

    #[test]
    fn accepts_empty_tables_and_decodes_windows_text_encodings() {
        let text = "Interface: 10.0.0.10 --- 0x6\r\n";
        let mut little_endian = vec![0xff, 0xfe];
        let mut big_endian = vec![0xfe, 0xff];
        for unit in text.encode_utf16() {
            little_endian.extend(unit.to_le_bytes());
            big_endian.extend(unit.to_be_bytes());
        }
        for bytes in [text.as_bytes(), &little_endian, &big_endian] {
            let report = parse_report(&decode_report(bytes).unwrap()).unwrap();
            assert!(inspect(&report).contains("0 dynamic, 0 static, 0 distinct IPv4 addresses"));
        }
        assert_eq!(
            inspect(&parse_report("No ARP Entries Found.\n").unwrap()),
            "No mappings found.\n"
        );
        assert!(decode_report(&[0xff]).is_err());
        assert!(decode_report(&[0xff, 0xfe, 0x00]).is_err());
        assert!(decode_report(&[0xff, 0xfe, 0x00, 0xd8]).is_err());
    }
}
