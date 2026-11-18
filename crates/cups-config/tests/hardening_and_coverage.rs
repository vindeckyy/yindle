//! Comprehensive security-regression and parser coverage tests for `cups-config`.

use cups_config::*;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn security_defaults_and_prohibited_env() {
    assert_eq!(Satisfy::default(), Satisfy::All);

    let files = CupsFilesConfig::defaults();
    assert_eq!(
        files.document_root.as_deref(),
        Some("/usr/share/cups/doc-root")
    );
    assert_eq!(
        files.system_group_names,
        vec!["sys", "root", "wheel", "lpadmin"]
    );

    let pol = default_policy();
    assert!(pol.sub_values.contains(&"notify-recipient-uri".to_string()));
    assert!(pol.ops.iter().all(|o| o.loc.satisfy == Satisfy::All));
    assert!(pol
        .ops
        .iter()
        .any(|o| o.op == u32::from(ipp_codec::ops::op::CUPS_GET_DEVICES)));

    for var in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_CUSTOM_ANYTHING",
        "ld_preload",
        "GCONV_PATH",
        "PATH",
        "IFS",
        "ENV",
        "BASH_ENV",
        "PYTHONPATH",
        "PERL5LIB",
        "RUBYLIB",
        "NODE_OPTIONS",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "DEVICE_URI",
    ] {
        assert!(is_prohibited_env(var), "{var} must be prohibited");
    }
    assert!(!is_prohibited_env("TZ"));
    assert!(!is_prohibited_env("MY_SAFE_APP_VAR"));
}

#[test]
fn types_parsers_and_conversions() {
    for (s, lvl) in [
        ("debug2", LogLevel::Debug2),
        ("debug", LogLevel::Debug),
        ("info", LogLevel::Info),
        ("notice", LogLevel::Notice),
        ("warn", LogLevel::Warn),
        ("error", LogLevel::Error),
        ("crit", LogLevel::Crit),
        ("alert", LogLevel::Alert),
        ("emerg", LogLevel::Emerg),
        ("none", LogLevel::None),
    ] {
        assert_eq!(LogLevel::parse(s), Some(lvl));
        assert_eq!(lvl.as_str(), s);
        assert_eq!(lvl.to_string(), s);
    }
    assert_eq!(LogLevel::parse("loud"), None);

    let (f_none, bad) = FatalErrors::parse(None);
    assert_eq!(f_none, FatalErrors::NONE);
    assert_eq!(bad, Vec::<String>::new());

    let (f_all, bad) = FatalErrors::parse(Some(
        "all -browse -config -listen -log -permissions -unknown none",
    ));
    assert!(!f_all.has(FatalErrors::BROWSE));
    assert!(!f_all.has(FatalErrors::CONFIG));
    assert!(!f_all.has(FatalErrors::LISTEN));
    assert!(!f_all.has(FatalErrors::LOG));
    assert!(!f_all.has(FatalErrors::PERMISSIONS));
    assert!(!f_all.has(FatalErrors::UNKNOWN));
    assert_eq!(bad, Vec::<String>::new());

    let (f_some, bad) =
        FatalErrors::parse(Some("browse,config listen log permissions unknown bogus"));
    assert!(f_some.has(FatalErrors::BROWSE));
    assert!(f_some.has(FatalErrors::CONFIG));
    assert!(f_some.has(FatalErrors::LISTEN));
    assert!(f_some.has(FatalErrors::LOG));
    assert!(f_some.has(FatalErrors::PERMISSIONS));
    assert!(f_some.has(FatalErrors::UNKNOWN));
    assert_eq!(bad, vec!["bogus"]);

    assert_eq!(BrowseProtocols::parse("all"), Ok(BrowseProtocols::ALL));
    assert_eq!(
        BrowseProtocols::parse("dnssd, none"),
        Ok(BrowseProtocols::DNSSD)
    );
    assert_eq!(BrowseProtocols::parse("none"), Ok(BrowseProtocols(0)));
    assert_eq!(BrowseProtocols::parse("cups"), Err("cups".to_string()));

    let n4 = IpNet::from(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let n6 = IpNet::from(IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(n4.bits(), 32);
    assert_eq!(n6.bits(), 128);
}

#[test]
#[allow(clippy::too_many_lines)]
fn cupsd_all_directives_and_error_branches() {
    let conf = br"
# Every typed CUPSD_VAR
AutoPurgeJobs yes
BrowseDNSSDSubTypes _cups,_universal
BrowseIPPSOnly yes
BrowseWebIF yes
Browsing true
Classification confidential
ClassifyOverride 1
DefaultLanguage fr
DefaultLeaseDuration 1h
DefaultPaperSize A4
DefaultPolicy default
DefaultShared no
DirtyCleanInterval 45
DNSSDComputerName Office Printer
DNSSDHostName print.local
ErrorPolicy retry-job
FilterLimit 0x10
GSSServiceName IPP
IdleExitTimeout 2m
JobKillDelay 10
JobRetryLimit 010
JobRetryInterval 1w
KeepAlive off
LaunchdTimeout 30
LimitRequestBody 1g
LogDebugHistory 50
MaxActiveJobs 5
MaxClients 200
MaxClientsPerHost 20
MaxCopies 99
MaxEvents 50
MaxHoldTime 3h
MaxJobs 100
MaxJobsPerPrinter 25
MaxJobsPerUser 10
MaxJobTime 1d
MaxLeaseDuration 2d
MaxLogSize 512k
MaxRequestSize 10m
MaxSubscriptions 20
MaxSubscriptionsPerJob 5
MaxSubscriptionsPerPrinter 5
MaxSubscriptionsPerUser 5
MultipleOperationTimeout 60
PageLogFormat %p %u
PreserveJobFiles no
PreserveJobHistory yes
ReloadTimeout 15
RootCertDuration 120
ServerAdmin root@localhost
ServerName print.example.com
StrictConformance yes
Timeout 60
WebInterface disabled

# Special cupsd directives
FaxRetryInterval 40
FaxRetryLimit 3
SSLOptions AllowRC4 AllowSSL3 AllowDH DenyCBC DenyTLS1.0 MaxTLS1.0 MaxTLS1.1 MaxTLS1.2 MaxTLS1.3 MinTLS1.0 MinTLS1.1 MinTLS1.2 MinTLS1.3 NoSystem NoEmptyFragments None UnknownSSLOpt
SSLOptions
Port 631
Port 631
SSLPort 8631
Listen *:632
Listen 127.0.0.1:633
Listen [::1]:634
Listen ::1
Listen 127.0.0.1:ipp_not_num
Listen /tmp/pw-test.sock
Listen /tmp/pw-test.sock
Listen /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Listen nonexistent.invalid.host.example:631
BrowseProtocols dnssd
BrowseLocalProtocols
DefaultAuthType None
DefaultAuthType Basic
DefaultAuthType Bearer
DefaultAuthType Negotiate
DefaultAuthType Auto
DefaultAuthType BogusAuth
DefaultEncryption
DefaultEncryption Never
DefaultEncryption Required
DefaultEncryption IfRequested
DefaultEncryption BogusEnc
HostNameLookups off
HostNameLookups on
HostNameLookups double
HostNameLookups weird
AccessLogLevel all
AccessLogLevel actions
AccessLogLevel config
AccessLogLevel none
AccessLogLevel bogus
LogLevel debug2
LogLevel bogus
LogTimeFormat standard
LogTimeFormat usecs
LogTimeFormat bogus
ReadyPaperSizes Letter, A4, Legal
ServerTokens ProductOnly
ServerTokens Major
ServerTokens Minor
ServerTokens Minimal
ServerTokens OS
ServerTokens Full
ServerTokens None
ServerTokens BogusTok
ServerAlias host1.local, host2.local host1.local
FilterNice 10
FilterNice 99
FileDevice No
";
    let mut cfg = CupsdConfig::defaults();
    cfg.fatal_errors = FatalErrors::NONE;
    let mut diags = Diagnostics::default();
    assert!(read_cupsd_conf(
        &conf[..],
        "cupsd.conf",
        &mut cfg,
        &mut diags
    ));
    assert_eq!(cfg.filter_limit, 16);
    assert_eq!(cfg.job_retry_limit, 3);
    assert_eq!(cfg.job_retry_interval, 40);
    assert_eq!(cfg.filter_nice, 10);
    assert_eq!(cfg.ready_paper_sizes, vec!["Letter", "A4", "Legal"]);
    assert_eq!(cfg.server_aliases, vec!["host1.local", "host2.local"]);
    assert_eq!(cfg.max_request_size, 10 * 1024 * 1024);
    assert_eq!(cfg.max_log_size, 512 * 1024);
    assert_eq!(cfg.preserve_job_files, 0);
    assert_eq!(cfg.preserve_job_history, i32::MAX);
    assert!(diags
        .entries
        .iter()
        .any(|d| d.message.contains("Please move")));
    assert!(diags
        .entries
        .iter()
        .any(|d| d.message.contains("Duplicate listen")));
    assert!(diags.entries.iter().any(|d| d.message.contains("too long")));

    // Default listeners helper
    let mut empty_cfg = CupsdConfig::defaults();
    default_listeners(&mut empty_cfg);
    assert_eq!(empty_cfg.listeners.len(), 2);

    // BrowseProtocols unknown aborts loop
    let (_c, d) = parse_cupsd_conf(b"BrowseLocalProtocols bogus\n".as_slice(), "x");
    assert!(d.has_errors());
}

#[test]
fn cupsd_var_coercion_error_paths() {
    let bad_lines = br"
MaxClients
MaxClients abc
MaxClients 99999999999999
MaxRequestSize
MaxRequestSize abc
MaxRequestSize 10x
MaxRequestSize 99999999999999999999999
Timeout
Timeout abc
Timeout 10z
Timeout 999999999999
Browsing
Browsing maybe
DefaultLanguage
";
    let mut cfg = CupsdConfig::defaults();
    cfg.fatal_errors = FatalErrors::NONE;
    let mut diags = Diagnostics::default();
    assert!(read_cupsd_conf(
        &bad_lines[..],
        "bad.conf",
        &mut cfg,
        &mut diags
    ));
    assert!(diags.entries.len() >= 12);

    // Fatal config error aborts early
    let mut cfg_fatal = CupsdConfig::defaults();
    cfg_fatal.fatal_errors = FatalErrors::CONFIG;
    let mut d2 = Diagnostics::default();
    assert!(!read_cupsd_conf(
        b"MaxClients abc\n".as_slice(),
        "f",
        &mut cfg_fatal,
        &mut d2
    ));

    // Fatal unknown aborts early
    let mut cfg_unk = CupsdConfig::defaults();
    cfg_unk.fatal_errors = FatalErrors::UNKNOWN;
    let mut d3 = Diagnostics::default();
    assert!(!read_cupsd_conf(
        b"TotallyUnknown 1\n".as_slice(),
        "f",
        &mut cfg_unk,
        &mut d3
    ));
}

#[test]
fn location_and_policy_block_edge_cases_and_errors() {
    let conf = br"
<Location /dup>
  <Limit ALL GET HEAD OPTIONS POST PUT TRACE DELETE BOGUSMETHOD>
    Order deny,allow
  </Limit>
  <Limit>
  MissingValDirective
  UnknownLocDir x
  Order bogusorder
</Location>
<Location /dup>
  Order allow,deny
</Location>

<Policy p1>
  JobPrivateAccess default custom_user
  JobPrivateValues default job-sheets
  SubscriptionPrivateAccess default sub_user
  SubscriptionPrivateValues default notify-lease-duration
  <Limit All Print-Job UnknownOpName>
    Order deny,allow
    JobPrivateAccess default
    MissingInLimit
    UnknownPolDir y
    Order bogus
  </Limit>
  <Limit>
  OutsideLimitDir z
  <Limit UnknownOnlyOp>
    Order deny,allow
  </Limit>
</Policy>
<Policy p1>
  <Limit Print-Job>
    Order deny,allow
</Policy>
";
    let mut cfg = CupsdConfig::defaults();
    cfg.fatal_errors = FatalErrors::NONE;
    let mut diags = Diagnostics::default();
    assert!(read_cupsd_conf(
        &conf[..],
        "blocks.conf",
        &mut cfg,
        &mut diags
    ));
    assert!(diags
        .entries
        .iter()
        .any(|d| d.message.contains("Duplicate <Location")));
    assert!(diags
        .entries
        .iter()
        .any(|d| d.message.contains("Duplicate <Policy")));
    assert!(diags
        .entries
        .iter()
        .any(|d| d.message.contains("Missing </Limit>")));
    assert!(diags
        .entries
        .iter()
        .any(|d| d.message.contains("Unknown request type")));
    assert!(diags
        .entries
        .iter()
        .any(|d| d.message.contains("Bad IPP operation name")));

    // Unexpected EOF in Location and Policy (both non-fatal and fatal)
    let mut c1 = CupsdConfig::defaults();
    c1.fatal_errors = FatalErrors::CONFIG;
    let mut d1 = Diagnostics::default();
    assert!(!read_cupsd_conf(
        b"<Location /eof>\n".as_slice(),
        "x",
        &mut c1,
        &mut d1
    ));
    assert!(d1
        .entries
        .iter()
        .any(|d| d.message.contains("Unexpected end-of-file")));

    let mut c2 = CupsdConfig::defaults();
    c2.fatal_errors = FatalErrors::CONFIG;
    let mut d2 = Diagnostics::default();
    assert!(!read_cupsd_conf(
        b"<Policy eof>\n".as_slice(),
        "x",
        &mut c2,
        &mut d2
    ));
    assert!(d2
        .entries
        .iter()
        .any(|d| d.message.contains("Unexpected end-of-file")));

    // >100 ops in a single <Limit>
    let many_ops = format!(
        "<Policy big>\n<Limit {}>\nOrder deny,allow\n</Limit>\n</Policy>\n",
        vec!["Print-Job"; 105].join(" ")
    );
    let (_c3, d3) = parse_cupsd_conf(many_ops.as_bytes(), "big");
    assert!(d3
        .entries
        .iter()
        .any(|d| d.message.contains("Too many operations")));
}

#[test]
#[allow(clippy::too_many_lines)]
fn cups_files_all_directives_and_error_paths() {
    let dir = std::env::temp_dir().join(format!("pw-cfg-files-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let oauth_file = dir.join("oauth.grp");
    std::fs::write(&oauth_file, b"alice\n").unwrap();

    let conf = format!(
        r#"
FatalErrors none
AccessLog /var/log/cups/access_log
CacheDir /var/cache/cups
ConfigFilePerm 0600
CreateSelfSignedCerts yes
DataDir /usr/share/cups
DocumentRoot /usr/share/cups/doc-root
ErrorLog /var/log/cups/error_log
LogFilePerm 0640
OAuthScopes openid
OAuthServer https://idp.example.com
PageLog /var/log/cups/page_log
Printcap /run/cups/printcap
PrintcapFormat bsd
PrintcapFormat plist
PrintcapFormat solaris
PrintcapFormat badfmt
RemoteRoot remroot
RequestRoot /var/spool/cups
ServerBin {}
ServerKeychain ssl
ServerRoot {}
StateDir /run/cups
StripUserDomain yes
SyncOnClose yes
SystemGroupAuthKey system.print.admin
TempDir {}
FileDevice No
FileDevice Yes
FileDevice ^/dev/lp[0-9]+$
FileDevice /bad/no/caret
Group 100
Group staff
Group missinggrp
LogFileGroup 200
LogFileGroup staff
LogFileGroup missinggrp
OAuthGroup admins {}
OAuthGroup relgrp oauth.grp
OAuthGroup missing missing.grp
PassEnv TZ, LANG LD_PRELOAD HTTP_PROXY
SetEnv MY_VAR hello
SetEnv NO_VAL
SetEnv LD_LIBRARY_PATH /tmp
PeerCred off
PeerCred on
PeerCred root-only
PeerCred bogus
Sandboxing off
Sandboxing relaxed
Sandboxing strict
Sandboxing bogus
SystemGroup "my admin" 'sec grp' missinggrp
User 1000
User 0
User lp
User root
User missinguser
ServerCertificate /etc/cups/ssl/a.crt
ServerKey /etc/cups/ssl/a.key
ConfigFilePerm
ConfigFilePerm abc
ConfigFilePerm 999
ServerBin
ServerBin /nonexistent/serverbin/path
UnknownFilesDir foo
"#,
        dir.display(),
        dir.display(),
        dir.display(),
        oauth_file.display()
    );

    let mut cfg = CupsFilesConfig::defaults();
    let mut fatal = FatalErrors::NONE;
    let mut diags = Diagnostics::default();
    let ok = read_cups_files_conf(
        Cursor::new(conf.as_bytes()),
        "cups-files.conf",
        &mut cfg,
        &dir.to_string_lossy(),
        &mut fatal,
        &mut diags,
        &|g| match g {
            "staff" => Some(50),
            "my admin" => Some(51),
            "sec grp" => Some(52),
            _ => None,
        },
        &|u| match u {
            "lp" => Some(7),
            "root" => Some(0),
            _ => None,
        },
    );
    assert!(ok);
    assert_eq!(cfg.config_file_perm, 0o600);
    assert_eq!(cfg.log_file_perm, 0o640);
    assert_eq!(cfg.user, 7);
    assert_eq!(cfg.group, 50);
    assert_eq!(cfg.log_file_group, Some(50));
    assert_eq!(cfg.pass_env, vec!["TZ"]);
    assert_eq!(cfg.set_env, vec![("MY_VAR".into(), "hello".into())]);
    // Explicit SystemGroup replaced the default list!
    assert_eq!(cfg.system_group_names, vec!["my admin", "sec grp"]);
    assert_eq!(cfg.system_groups, vec![51, 52]);
    assert_eq!(cfg.oauth_groups.len(), 2);
    assert!(cfg.strip_user_domain);
    assert!(cfg.sync_on_close);
    assert!(diags
        .entries
        .iter()
        .any(|d| d.message.contains("LD_PRELOAD")));
    assert!(diags
        .entries
        .iter()
        .any(|d| d.message.contains("LD_LIBRARY_PATH")));
    assert!(diags.entries.iter().any(|d| d.message.contains("User 0")));
    assert!(diags.entries.iter().any(|d| d.message.contains("UID=0")));

    // Fatal config errors abort read_cups_files_conf cleanly
    let mut cfg2 = CupsFilesConfig::defaults();
    let mut fat2 = FatalErrors::CONFIG;
    let mut d2 = Diagnostics::default();
    assert!(!read_cups_files_conf(
        b"PassEnv LD_PRELOAD\n".as_slice(),
        "f",
        &mut cfg2,
        "/etc/cups",
        &mut fat2,
        &mut d2,
        &|_| None,
        &|_| None,
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_and_paths_resolution_and_lexer_utf8() {
    // Lexer multi-byte UTF-8 and \n \r escapes
    let mut lines = conf_lines("SetEnv U cafés\\n\\r日本語\n".as_bytes());
    let l = lines.next().unwrap().unwrap();
    assert_eq!(l.name, "SetEnv");
    assert_eq!(l.value.as_deref(), Some("U cafés\n\r日本語"));
    assert_eq!(lines.linenum(), 1);
    assert!(lines.next().is_none());

    // `Paths::resolve` + `load()` lifecycle
    let dir = std::env::temp_dir().join(format!("pw-cfg-load-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let paths = Paths::resolve(Some(&dir));
    assert_eq!(paths.server_root, dir);

    // Missing cupsd.conf -> ok == false
    let missing = load(&paths);
    assert!(!missing.ok);

    // Valid cupsd.conf with missing DefaultPolicy + absent cups-files.conf -> synthesizes default policy & resolves default system groups
    std::fs::write(
        &paths.cupsd_conf,
        b"DefaultPolicy nonexistent\nLogLevel info\n",
    )
    .unwrap();
    let res1 = load(&paths);
    assert!(res1.ok);
    assert_eq!(res1.config.cupsd.default_policy.as_deref(), Some("default"));
    assert_ne!(res1.config.cupsd.listeners, Vec::<Listener>::new());
    assert_ne!(res1.config.files.system_group_names, Vec::<String>::new());
    assert_ne!(res1.config.files.system_groups, Vec::<u32>::new()); // at least `root` resolves on Linux

    // Present cups-files.conf + valid cupsd.conf
    std::fs::write(&paths.cups_files_conf, b"SystemGroup root\nFileDevice No\n").unwrap();
    let res2 = load(&paths);
    assert!(res2.ok);
    assert_eq!(res2.config.files.system_group_names, vec!["root"]);
    assert_eq!(res2.config.files.system_groups, vec![0]);

    // Fatal error inside cups-files.conf and cupsd.conf
    std::fs::write(&paths.cups_files_conf, b"FatalErrors config\nUser 0\n").unwrap();
    let res3 = load(&paths);
    assert!(!res3.ok);

    // Unreadable cups-files.conf (directory instead of file)
    let _ = std::fs::remove_file(&paths.cups_files_conf);
    std::fs::create_dir_all(&paths.cups_files_conf).unwrap();
    let res4 = load(&paths);
    assert!(!res4.ok);

    let _ = std::fs::remove_dir_all(&dir);
}
