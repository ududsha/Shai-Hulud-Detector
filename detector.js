#!/usr/bin/env node

/**
 * Shai-Hulud 2.0 Global NPM Package Security Checker
 * 
 * This script checks your globally installed npm packages against the
 * Shai-Hulud 2.0 compromised packages list.
 * 
 * Usage:
 *   1. Save npm list output: npm list -g --depth=10 --json > global-packages.json
 *   2. Run this script: node check-packages.js at your codes root level
 * 
 * Or run directly with inline command:
 *   node check-packages.js --inline
 */

const https = require('https');
const { execSync } = require('child_process');
const fs = require('fs');

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m'
};

// URLs for compromised packages lists
const COMPROMISED_SOURCES = [
  'https://raw.githubusercontent.com/gensecaihq/Shai-Hulud-2.0-Detector/main/compromised-packages.json',
  'https://raw.githubusercontent.com/tenable/shai-hulud-second-coming-affected-packages/main/list.json'
];

/**
 * Fetch data from URL
 */
function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        if (res.statusCode === 200) {
          resolve(data);
        } else {
          reject(new Error(`Failed to fetch ${url}: ${res.statusCode}`));
        }
      });
    }).on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Fetch compromised packages list
 */
async function fetchCompromisedPackages() {
  console.log(`${colors.blue}Fetching compromised packages list...${colors.reset}`);
  
  for (const url of COMPROMISED_SOURCES) {
    try {
      const data = await fetchUrl(url);
      const parsed = JSON.parse(data);
      console.log(`${colors.green}✓ Successfully fetched compromised packages from source${colors.reset}`);
      return parsed;
    } catch (err) {
      console.warn(`${colors.yellow}⚠ Failed to fetch from ${url}: ${err.message}${colors.reset}`);
    }
  }
  
  throw new Error('Failed to fetch compromised packages from all sources');
}

/**
 * Get global npm packages
 */
function getGlobalPackages(useInline = false) {
  console.log(`${colors.blue}Retrieving global npm packages...${colors.reset}`);
  
  if (!useInline && fs.existsSync('global-packages.json')) {
    console.log(`${colors.cyan}Reading from global-packages.json${colors.reset}`);
    const data = fs.readFileSync('global-packages.json', 'utf8');
    return JSON.parse(data);
  }
  
  console.log(`${colors.cyan}Running: npm list -g --depth=10 --json${colors.reset}`);
  try {
    const output = execSync('npm list -g --depth=10 --json', {
      encoding: 'utf8',
      maxBuffer: 10 * 1024 * 1024 // 10MB buffer
    });
    return JSON.parse(output);
  } catch (err) {
    // npm list returns non-zero exit code if there are issues, but still outputs JSON
    if (err.stdout) {
      return JSON.parse(err.stdout);
    }
    throw err;
  }
}

/**
 * Flatten npm dependency tree
 */
function flattenDependencies(deps, result = new Map()) {
  if (!deps) return result;
  
  for (const [name, info] of Object.entries(deps)) {
    if (info.version) {
      result.set(`${name}@${info.version}`, {
        name,
        version: info.version,
        path: info.path || 'unknown'
      });
    }
    
    if (info.dependencies) {
      flattenDependencies(info.dependencies, result);
    }
  }
  
  return result;
}

/**
 * Parse compromised packages list (supports multiple formats)
 */
function parseCompromisedList(data) {
  const compromised = new Map();
  
  // Handle gensecaihq format
  if (data.packages && Array.isArray(data.packages)) {
    data.packages.forEach(pkg => {
      const key = `${pkg.name}@${pkg.version}`;
      compromised.set(key, {
        name: pkg.name,
        version: pkg.version,
        severity: pkg.severity || 'high',
        source: pkg.source || 'unknown'
      });
    });
  }
  // Handle Tenable format (array of objects)
  else if (Array.isArray(data)) {
    data.forEach(pkg => {
      const key = `${pkg.package}@${pkg.version}`;
      compromised.set(key, {
        name: pkg.package,
        version: pkg.version,
        severity: 'critical',
        source: 'tenable'
      });
    });
  }
  // Handle simple array format
  else if (data.compromisedPackages && Array.isArray(data.compromisedPackages)) {
    data.compromisedPackages.forEach(pkgStr => {
      const [name, version] = pkgStr.split('@');
      compromised.set(pkgStr, {
        name,
        version,
        severity: 'high',
        source: 'list'
      });
    });
  }
  
  return compromised;
}

/**
 * Check for compromised packages
 */
function checkForCompromised(installedPackages, compromisedList) {
  const found = [];
  
  for (const [key, pkg] of installedPackages) {
    if (compromisedList.has(key)) {
      const compromisedInfo = compromisedList.get(key);
      found.push({
        ...pkg,
        ...compromisedInfo
      });
    }
  }
  
  return found;
}

/**
 * Display results
 */
function displayResults(compromisedFound, totalPackages) {
  console.log('\n' + '='.repeat(80));
  console.log(`${colors.bold}${colors.cyan}SCAN RESULTS${colors.reset}`);
  console.log('='.repeat(80));
  
  console.log(`\nTotal packages scanned: ${colors.blue}${totalPackages}${colors.reset}`);
  console.log(`Compromised packages found: ${compromisedFound.length > 0 ? colors.red : colors.green}${compromisedFound.length}${colors.reset}`);
  
  if (compromisedFound.length === 0) {
    console.log(`\n${colors.green}${colors.bold}✓ No compromised packages detected!${colors.reset}`);
    console.log(`${colors.green}Your global npm packages appear to be clean.${colors.reset}`);
    return;
  }
  
  console.log(`\n${colors.red}${colors.bold}⚠ CRITICAL: Compromised packages detected!${colors.reset}\n`);
  
  compromisedFound.forEach((pkg, index) => {
    console.log(`${colors.red}${index + 1}. ${pkg.name}@${pkg.version}${colors.reset}`);
    console.log(`   ${colors.yellow}Severity: ${pkg.severity.toUpperCase()}${colors.reset}`);
    console.log(`   Path: ${pkg.path}`);
    console.log('');
  });
  
  console.log('='.repeat(80));
  console.log(`${colors.red}${colors.bold}IMMEDIATE ACTIONS REQUIRED:${colors.reset}`);
  console.log('='.repeat(80));
  console.log(`
1. ${colors.yellow}DO NOT RUN any of the compromised packages${colors.reset}
2. ${colors.yellow}Uninstall immediately:${colors.reset}`);
  
  compromisedFound.forEach(pkg => {
    console.log(`   npm uninstall -g ${pkg.name}`);
  });
  
  console.log(`
3. ${colors.yellow}Assume credentials are compromised:${colors.reset}
   - Rotate all GitHub tokens and npm tokens
   - Check for unauthorized GitHub repositories with "Sha1-Hulud: The Second Coming"
   - Review GitHub Actions workflows for suspicious runners named "SHA1HULUD"
   - Scan for files: setup_bun.js, bun_environment.js, actionsSecrets.json

4. ${colors.yellow}Clear npm cache:${colors.reset}
   npm cache clean --force

5. ${colors.yellow}Scan your system for malicious files:${colors.reset}
   - Look for .truffler-cache directory
   - Check ~/.ssh, ~/.aws, ~/.config for unauthorized changes
   
6. ${colors.yellow}Review resources:${colors.reset}
   - Wiz Investigation: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
   - Unit 42 Report: https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
   - Tenable FAQ: https://www.tenable.com/blog/faq-about-sha1-hulud-2-0-the-second-coming-of-the-npm-supply-chain-campaign
`);
  
  console.log('='.repeat(80));
}

/**
 * Main execution
 */
async function main() {
  console.log(`${colors.bold}${colors.magenta}`);
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║   Shai-Hulud 2.0 Global NPM Package Security Checker          ║');
  console.log('║   Protecting against supply chain attacks                     ║');
  console.log('╚════════════════════════════════════════════════════════════════╝');
  console.log(colors.reset);
  
  const useInline = process.argv.includes('--inline');
  
  try {
    // Fetch compromised packages list
    const compromisedData = await fetchCompromisedPackages();
    const compromisedList = parseCompromisedList(compromisedData);
    
    console.log(`${colors.green}✓ Loaded ${compromisedList.size} compromised package entries${colors.reset}\n`);
    
    // Get global packages
    const globalData = getGlobalPackages(useInline);
    const installedPackages = flattenDependencies(globalData.dependencies);
    
    console.log(`${colors.green}✓ Found ${installedPackages.size} installed packages${colors.reset}\n`);
    
    // Check for compromised packages
    const compromisedFound = checkForCompromised(installedPackages, compromisedList);
    
    // Display results
    displayResults(compromisedFound, installedPackages.size);
    
    // Exit with appropriate code
    process.exit(compromisedFound.length > 0 ? 1 : 0);
    
  } catch (err) {
    console.error(`${colors.red}${colors.bold}Error: ${err.message}${colors.reset}`);
    console.error(err.stack);
    process.exit(2);
  }
}

// Run if executed directly
if (require.main === module) {
  main();
}

module.exports = { fetchCompromisedPackages, getGlobalPackages, checkForCompromised };