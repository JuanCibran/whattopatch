/**
 * Product catalog for "Your stack". Matching runs in the browser against
 * "vendor | product | title" text, so a user's list never leaves their device.
 *
 * `any` must match; `all` (when present) must also match. Both are regex sources,
 * tested case-insensitively.
 */
export type StackEntry = {
  id: string;
  label: string;
  group: StackGroup;
  any: string;
  all?: string;
  /** Shown under the label when the match covers more than the name suggests. */
  note?: string;
};

export type StackGroup =
  | "Firewalls and VPNs"
  | "Microsoft"
  | "Servers and virtualization"
  | "Web apps and dev tools"
  | "File transfer and remote access"
  | "Browsers, phones and desktop"
  | "Storage and cameras";

export const STACK_GROUPS: StackGroup[] = [
  "Firewalls and VPNs",
  "Microsoft",
  "Servers and virtualization",
  "Web apps and dev tools",
  "File transfer and remote access",
  "Browsers, phones and desktop",
  "Storage and cameras",
];

export const STACK_CATALOG: StackEntry[] = [
  // Firewalls and VPNs
  { id: "fortinet", label: "Fortinet", group: "Firewalls and VPNs", any: "\\bforti", note: "FortiGate, FortiOS, FortiWeb, FortiManager and other Forti products" },
  { id: "paloalto", label: "Palo Alto Networks", group: "Firewalls and VPNs", any: "palo alto|pan-os|globalprotect" },
  { id: "cisco-firewall", label: "Cisco ASA and Firepower", group: "Firewalls and VPNs", any: "^cisco", all: "\\basa\\b|adaptive security|firepower|\\bftd\\b|secure firewall" },
  { id: "cisco-ios", label: "Cisco IOS and IOS XE", group: "Firewalls and VPNs", any: "^cisco", all: "\\bios\\b|ios xe|ios xr" },
  { id: "cisco", label: "Cisco (all products)", group: "Firewalls and VPNs", any: "^cisco" },
  { id: "ivanti", label: "Ivanti and Pulse Secure", group: "Firewalls and VPNs", any: "ivanti|pulse secure|pulse connect" },
  { id: "citrix", label: "Citrix NetScaler", group: "Firewalls and VPNs", any: "citrix|netscaler" },
  { id: "f5", label: "F5 BIG-IP", group: "Firewalls and VPNs", any: "\\bf5\\b|big-?ip" },
  { id: "checkpoint", label: "Check Point", group: "Firewalls and VPNs", any: "check ?point" },
  { id: "sonicwall", label: "SonicWall", group: "Firewalls and VPNs", any: "sonicwall|sonicos" },
  { id: "juniper", label: "Juniper", group: "Firewalls and VPNs", any: "juniper|junos" },
  { id: "sophos", label: "Sophos", group: "Firewalls and VPNs", any: "sophos" },
  { id: "watchguard", label: "WatchGuard", group: "Firewalls and VPNs", any: "watchguard|fireware" },
  { id: "zyxel", label: "Zyxel", group: "Firewalls and VPNs", any: "zyxel" },
  { id: "barracuda", label: "Barracuda", group: "Firewalls and VPNs", any: "barracuda" },
  { id: "mikrotik", label: "MikroTik", group: "Firewalls and VPNs", any: "mikrotik|routeros" },
  { id: "ubiquiti", label: "Ubiquiti UniFi", group: "Firewalls and VPNs", any: "ubiquiti|unifi" },
  { id: "tplink", label: "TP-Link", group: "Firewalls and VPNs", any: "tp-?link" },
  { id: "dlink", label: "D-Link", group: "Firewalls and VPNs", any: "d-?link" },
  { id: "netgear", label: "Netgear", group: "Firewalls and VPNs", any: "netgear" },
  { id: "draytek", label: "DrayTek", group: "Firewalls and VPNs", any: "draytek" },
  { id: "aruba", label: "HPE Aruba", group: "Firewalls and VPNs", any: "aruba" },
  { id: "arista", label: "Arista", group: "Firewalls and VPNs", any: "arista" },
  { id: "mitel", label: "Mitel", group: "Firewalls and VPNs", any: "mitel" },

  // Microsoft
  { id: "ms-windows", label: "Windows and Windows Server", group: "Microsoft", any: "^microsoft", all: "windows|win32k|smb|ntlm|kerberos|clfs|common log file|print spooler|mshtml|internet explorer|hyper-v|active directory|remote desktop|\\brdp\\b|lsass|kernel" },
  { id: "ms-exchange", label: "Exchange Server", group: "Microsoft", any: "^microsoft", all: "exchange" },
  { id: "ms-sharepoint", label: "SharePoint", group: "Microsoft", any: "^microsoft", all: "sharepoint" },
  { id: "ms-office", label: "Office and Outlook", group: "Microsoft", any: "^microsoft", all: "\\boffice\\b|\\boutlook\\b|\\bword\\b|\\bexcel\\b|powerpoint|\\bpublisher\\b|\\bvisio\\b|microsoft 365" },
  { id: "ms-dotnet", label: ".NET and Visual Studio", group: "Microsoft", any: "^microsoft", all: "\\.net\\b|visual studio" },
  { id: "microsoft", label: "Microsoft (all products)", group: "Microsoft", any: "^microsoft" },

  // Servers and virtualization
  { id: "vmware", label: "VMware ESXi and vCenter", group: "Servers and virtualization", any: "vmware|esxi|vcenter|vsphere" },
  { id: "linux", label: "Linux kernel", group: "Servers and virtualization", any: "linux", all: "kernel" },
  { id: "redhat", label: "Red Hat", group: "Servers and virtualization", any: "red ?hat" },
  { id: "nutanix", label: "Nutanix", group: "Servers and virtualization", any: "nutanix" },
  { id: "proxmox", label: "Proxmox", group: "Servers and virtualization", any: "proxmox" },
  { id: "veeam", label: "Veeam", group: "Servers and virtualization", any: "veeam" },
  { id: "commvault", label: "Commvault", group: "Servers and virtualization", any: "commvault" },
  { id: "oracle", label: "Oracle (WebLogic, E-Business Suite, Java)", group: "Servers and virtualization", any: "^oracle|weblogic|peoplesoft|e-business suite" },
  { id: "sap", label: "SAP", group: "Servers and virtualization", any: "\\bsap\\b|netweaver" },
  { id: "ibm", label: "IBM", group: "Servers and virtualization", any: "^ibm\\b" },
  { id: "hpe", label: "HPE and HP", group: "Servers and virtualization", any: "hewlett|\\bhpe\\b|\\bhp\\b" },
  { id: "dell", label: "Dell", group: "Servers and virtualization", any: "\\bdell\\b" },
  { id: "openssh", label: "OpenSSH", group: "Servers and virtualization", any: "openssh" },
  { id: "openssl", label: "OpenSSL", group: "Servers and virtualization", any: "openssl" },
  { id: "trendmicro", label: "Trend Micro", group: "Servers and virtualization", any: "trend ?micro" },
  { id: "zoho", label: "Zoho ManageEngine", group: "Servers and virtualization", any: "zoho|manageengine" },
  { id: "papercut", label: "PaperCut", group: "Servers and virtualization", any: "papercut" },
  { id: "exim", label: "Exim mail server", group: "Servers and virtualization", any: "\\bexim\\b" },

  // Web apps and dev tools
  { id: "wordpress", label: "WordPress and plugins", group: "Web apps and dev tools", any: "wordpress|\\bwp\\b" },
  { id: "apache-httpd", label: "Apache HTTP Server", group: "Web apps and dev tools", any: "apache", all: "http server|httpd" },
  { id: "tomcat", label: "Apache Tomcat", group: "Web apps and dev tools", any: "tomcat" },
  { id: "apache", label: "Apache (all projects)", group: "Web apps and dev tools", any: "apache" },
  { id: "log4j", label: "Log4j", group: "Web apps and dev tools", any: "log4j" },
  { id: "nginx", label: "nginx", group: "Web apps and dev tools", any: "nginx" },
  { id: "php", label: "PHP", group: "Web apps and dev tools", any: "\\bphp\\b" },
  { id: "drupal", label: "Drupal", group: "Web apps and dev tools", any: "drupal" },
  { id: "joomla", label: "Joomla", group: "Web apps and dev tools", any: "joomla" },
  { id: "magento", label: "Adobe Commerce and Magento", group: "Web apps and dev tools", any: "magento|adobe commerce" },
  { id: "atlassian", label: "Atlassian Confluence and Jira", group: "Web apps and dev tools", any: "atlassian|confluence|\\bjira\\b" },
  { id: "gitlab", label: "GitLab", group: "Web apps and dev tools", any: "gitlab" },
  { id: "jenkins", label: "Jenkins", group: "Web apps and dev tools", any: "jenkins" },
  { id: "jetbrains", label: "JetBrains TeamCity", group: "Web apps and dev tools", any: "jetbrains|teamcity" },
  { id: "sitecore", label: "Sitecore", group: "Web apps and dev tools", any: "sitecore" },
  { id: "zimbra", label: "Zimbra", group: "Web apps and dev tools", any: "zimbra" },
  { id: "roundcube", label: "Roundcube", group: "Web apps and dev tools", any: "roundcube" },
  { id: "moodle", label: "Moodle", group: "Web apps and dev tools", any: "moodle" },
  { id: "grafana", label: "Grafana", group: "Web apps and dev tools", any: "grafana" },
  { id: "kubernetes", label: "Kubernetes", group: "Web apps and dev tools", any: "kubernetes|ingress-nginx" },
  { id: "docker", label: "Docker", group: "Web apps and dev tools", any: "docker" },
  { id: "nodejs", label: "Node.js", group: "Web apps and dev tools", any: "node\\.js|nodejs" },
  { id: "spring", label: "Spring", group: "Web apps and dev tools", any: "\\bspring\\b|vmware tanzu spring" },

  // File transfer and remote access
  { id: "moveit", label: "MOVEit", group: "File transfer and remote access", any: "moveit" },
  { id: "progress", label: "Progress (MOVEit, Telerik, WhatsUp Gold)", group: "File transfer and remote access", any: "^progress\\b|telerik|whatsup gold|moveit" },
  { id: "nable", label: "N-able", group: "File transfer and remote access", any: "n-able" },
  { id: "goanywhere", label: "GoAnywhere", group: "File transfer and remote access", any: "goanywhere|fortra" },
  { id: "crushftp", label: "CrushFTP", group: "File transfer and remote access", any: "crushftp" },
  { id: "cleo", label: "Cleo", group: "File transfer and remote access", any: "\\bcleo\\b" },
  { id: "screenconnect", label: "ConnectWise ScreenConnect", group: "File transfer and remote access", any: "screenconnect|connectwise" },
  { id: "beyondtrust", label: "BeyondTrust", group: "File transfer and remote access", any: "beyondtrust|bomgar" },
  { id: "simplehelp", label: "SimpleHelp", group: "File transfer and remote access", any: "simplehelp" },
  { id: "solarwinds", label: "SolarWinds", group: "File transfer and remote access", any: "solarwinds" },
  { id: "kaseya", label: "Kaseya", group: "File transfer and remote access", any: "kaseya" },
  { id: "teamviewer", label: "TeamViewer", group: "File transfer and remote access", any: "teamviewer" },
  { id: "anydesk", label: "AnyDesk", group: "File transfer and remote access", any: "anydesk" },
  { id: "wingftp", label: "Wing FTP", group: "File transfer and remote access", any: "wing ftp" },

  // Browsers, phones and desktop
  { id: "chromium", label: "Chrome and Edge", group: "Browsers, phones and desktop", any: "chrom|\\bv8\\b|\\| edge\\b", note: "Includes Chromium flaws, which also hit Brave and Opera" },
  { id: "firefox", label: "Firefox and Thunderbird", group: "Browsers, phones and desktop", any: "mozilla|firefox|thunderbird" },
  { id: "apple", label: "Apple iPhone, iPad and Mac", group: "Browsers, phones and desktop", any: "^apple|ipados|macos|webkit|safari", note: "Apple often lists flaws as \"Multiple Products\"" },
  { id: "android", label: "Android", group: "Browsers, phones and desktop", any: "android" },
  { id: "samsung", label: "Samsung", group: "Browsers, phones and desktop", any: "samsung" },
  { id: "qualcomm", label: "Qualcomm and Arm chips", group: "Browsers, phones and desktop", any: "qualcomm|^arm\\b|\\bmali\\b" },
  { id: "adobe-reader", label: "Adobe Acrobat and Reader", group: "Browsers, phones and desktop", any: "^adobe", all: "acrobat|reader" },
  { id: "adobe", label: "Adobe (all products)", group: "Browsers, phones and desktop", any: "^adobe" },
  { id: "7zip", label: "7-Zip", group: "Browsers, phones and desktop", any: "7-?zip" },
  { id: "winrar", label: "WinRAR", group: "Browsers, phones and desktop", any: "winrar|rarlab" },
  { id: "zoom", label: "Zoom", group: "Browsers, phones and desktop", any: "\\bzoom\\b" },

  // Storage and cameras
  { id: "synology", label: "Synology", group: "Storage and cameras", any: "synology" },
  { id: "qnap", label: "QNAP", group: "Storage and cameras", any: "qnap" },
  { id: "hikvision", label: "Hikvision", group: "Storage and cameras", any: "hikvision" },
  { id: "dahua", label: "Dahua", group: "Storage and cameras", any: "dahua" },
];

const CATALOG_BY_ID = new Map(STACK_CATALOG.map((e) => [e.id, e]));

export const CUSTOM_PREFIX = "kw:";

export function entryFor(id: string): StackEntry | null {
  const known = CATALOG_BY_ID.get(id);
  if (known) return known;
  if (id.startsWith(CUSTOM_PREFIX)) {
    const keyword = id.slice(CUSTOM_PREFIX.length).trim();
    if (!keyword) return null;
    return { id, label: keyword, group: "Web apps and dev tools", any: escapeRegExp(keyword.toLowerCase()) };
  }
  return null;
}

export function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const compiled = new Map<string, { any: RegExp; all: RegExp | null }>();

function compile(entry: StackEntry) {
  let c = compiled.get(entry.id);
  if (!c) {
    c = { any: new RegExp(entry.any, "i"), all: entry.all ? new RegExp(entry.all, "i") : null };
    compiled.set(entry.id, c);
  }
  return c;
}

export function matchText(vendor: string, product: string, title: string): string {
  return `${vendor} | ${product} | ${title}`.toLowerCase();
}

export function entryMatches(entry: StackEntry, text: string): boolean {
  const c = compile(entry);
  return c.any.test(text) && (!c.all || c.all.test(text));
}

/** Returns the ids of the stack entries that match. */
export function matchingEntries(stack: StackEntry[], text: string): string[] {
  return stack.filter((e) => entryMatches(e, text)).map((e) => e.id);
}

/** Serialize/deserialize a stack for links ("#stack=fortinet,kw:jenkins"). */
export function encodeStack(ids: string[]): string {
  return ids.map((id) => encodeURIComponent(id)).join(",");
}

export function decodeStack(value: string | null | undefined): string[] {
  if (!value) return [];
  const ids = value
    .split(",")
    .map((part) => {
      try {
        return decodeURIComponent(part).trim();
      } catch {
        return "";
      }
    })
    .filter((id) => id && entryFor(id) !== null);
  return [...new Set(ids)].slice(0, 40);
}
