#!/usr/bin/env node

/**
 * Shai-Hulud 2.0 Deep Package Scanner
 * 
 * Scans package.json AND the entire dependency tree for compromised packages
 * 
 * Usage:
 *   node detector.js
 *   node detector.js /path/to/package.json
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

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

const COMPROMISED_SOURCES = [
  {
    name: 'GenSec HQ',
    url: 'https://raw.githubusercontent.com/gensecaihq/Shai-Hulud-2.0-Detector/main/compromised-packages.json'
  },
  {
    name: 'Tenable (JSON)',
    url: 'https://raw.githubusercontent.com/tenable/shai-hulud-second-coming-affected-packages/main/list.json'
  },
  {
    name: 'Cobenian',
    url: 'https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt'
  },
  {
    name: 'Tenable (MD)',
    url: 'https://raw.githubusercontent.com/tenable/shai-hulud-second-coming-affected-packages/main/list.md'
  }
];

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode === 200) {
          resolve(data);
        } else {
          reject(new Error(`HTTP ${res.statusCode}`));
        }
      });
    }).on('error', reject);
  });
}

function parseCompromisedList(data, sourceName) {
  const compromised = new Map();
  
  if (typeof data === 'string') {
    const lines = data.split('\n');
    lines.forEach(line => {
      line = line.trim();
      if (!line || line.startsWith('#') || line.startsWith('|')) return;
      
      if (line.includes('|')) {
        const parts = line.split('|').map(p => p.trim()).filter(Boolean);
        if (parts.length >= 2 && parts[0] && parts[1]) {
          const name = parts[0];
          const version = parts[1];
          if (name !== 'Package' && version !== 'Version') {
            if (!compromised.has(name)) {
              compromised.set(name, { versions: new Map(), sources: new Set() });
            }
            const pkg = compromised.get(name);
            if (!pkg.versions.has(version)) {
              pkg.versions.set(version, new Set());
            }
            pkg.versions.get(version).add(sourceName);
            pkg.sources.add(sourceName);
          }
        }
        return;
      }
      
      const match = line.match(/^([^:@]+)[:@](.+)$/);
      if (match) {
        const [, name, version] = match;
        const cleanName = name.trim();
        const cleanVersion = version.trim();
        if (!compromised.has(cleanName)) {
          compromised.set(cleanName, { versions: new Map(), sources: new Set() });
        }
        const pkg = compromised.get(cleanName);
        if (!pkg.versions.has(cleanVersion)) {
          pkg.versions.set(cleanVersion, new Set());
        }
        pkg.versions.get(cleanVersion).add(sourceName);
        pkg.sources.add(sourceName);
      }
    });
  } else if (typeof data === 'object') {
    if (data.packages && Array.isArray(data.packages)) {
      data.packages.forEach(pkg => {
        const name = pkg.name || pkg.package;
        const version = pkg.version;
        if (!compromised.has(name)) {
          compromised.set(name, { versions: new Map(), sources: new Set() });
        }
        const p = compromised.get(name);
        if (!p.versions.has(version)) {
          p.versions.set(version, new Set());
        }
        p.versions.get(version).add(sourceName);
        p.sources.add(sourceName);
      });
    } else if (Array.isArray(data)) {
      data.forEach(pkg => {
        const name = pkg.package || pkg.name;
        const version = pkg.version;
        if (!compromised.has(name)) {
          compromised.set(name, { versions: new Map(), sources: new Set() });
        }
        const p = compromised.get(name);
        if (!p.versions.has(version)) {
          p.versions.set(version, new Set());
        }
        p.versions.get(version).add(sourceName);
        p.sources.add(sourceName);
      });
    }
  }
  
  return compromised;
}

async function fetchAllCompromisedPackages() {
  const allCompromised = new Map();
  
  console.log(`${colors.blue}Fetching compromised packages from multiple sources...${colors.reset}\n`);
  
  for (let i = 0; i < COMPROMISED_SOURCES.length; i++) {
    const source = COMPROMISED_SOURCES[i];
    try {
      console.log(`Fetching source ${i + 1}/${COMPROMISED_SOURCES.length} (${source.name})...`);
      const data = await fetchUrl(source.url);
      
      let parsed;
      try {
        parsed = JSON.parse(data);
      } catch {
        parsed = data;
      }
      
      const sourceCompromised = parseCompromisedList(parsed, source.name);
      
      // Merge with all compromised
      for (const [name, pkgData] of sourceCompromised) {
        if (!allCompromised.has(name)) {
          allCompromised.set(name, { versions: new Map(), sources: new Set() });
        }
        const existing = allCompromised.get(name);
        
        for (const [version, sources] of pkgData.versions) {
          if (!existing.versions.has(version)) {
            existing.versions.set(version, new Set());
          }
          for (const src of sources) {
            existing.versions.get(version).add(src);
            existing.sources.add(src);
          }
        }
      }
      
      console.log(`${colors.green}✓ Success${colors.reset}`);
    } catch (err) {
      console.log(`${colors.yellow}⚠ Failed: ${err.message}${colors.reset}`);
    }
  }
  
  console.log(`\n${colors.green}Total unique packages: ${allCompromised.size}${colors.reset}\n`);
  return allCompromised;
}

function readPackageJson(packageJsonPath) {
  try {
    const content = fs.readFileSync(packageJsonPath, 'utf8');
    return JSON.parse(content);
  } catch (err) {
    throw new Error(`Failed to read package.json: ${err.message}`);
  }
}

function getAllInstalledPackages(nodeModulesPath, scanned = new Map()) {
  if (!fs.existsSync(nodeModulesPath)) {
    return scanned;
  }
  
  try {
    const entries = fs.readdirSync(nodeModulesPath, { withFileTypes: true });
    
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      
      // Handle scoped packages (@scope/package)
      if (entry.name.startsWith('@')) {
        const scopePath = path.join(nodeModulesPath, entry.name);
        const scopedPackages = fs.readdirSync(scopePath, { withFileTypes: true });
        
        for (const scopedPkg of scopedPackages) {
          if (!scopedPkg.isDirectory()) continue;
          
          const packageName = `${entry.name}/${scopedPkg.name}`;
          const packagePath = path.join(scopePath, scopedPkg.name);
          const packageJsonPath = path.join(packagePath, 'package.json');
          
          if (fs.existsSync(packageJsonPath) && !scanned.has(packageName)) {
            try {
              const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
              scanned.set(packageName, {
                version: pkg.version,
                path: packagePath
              });
              
              // Recursively scan nested node_modules
              const nestedNodeModules = path.join(packagePath, 'node_modules');
              if (fs.existsSync(nestedNodeModules)) {
                getAllInstalledPackages(nestedNodeModules, scanned);
              }
            } catch (err) {
              // Skip invalid package.json
            }
          }
        }
      } else {
        // Regular package
        const packageName = entry.name;
        const packagePath = path.join(nodeModulesPath, entry.name);
        const packageJsonPath = path.join(packagePath, 'package.json');
        
        if (fs.existsSync(packageJsonPath) && !scanned.has(packageName)) {
          try {
            const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
            scanned.set(packageName, {
              version: pkg.version,
              path: packagePath
            });
            
            // Recursively scan nested node_modules
            const nestedNodeModules = path.join(packagePath, 'node_modules');
            if (fs.existsSync(nestedNodeModules)) {
              getAllInstalledPackages(nestedNodeModules, scanned);
            }
          } catch (err) {
            // Skip invalid package.json
          }
        }
      }
    }
  } catch (err) {
    console.error(`${colors.yellow}Warning: Could not scan ${nodeModulesPath}: ${err.message}${colors.reset}`);
  }
  
  return scanned;
}

function scanAllPackages(projectRoot, compromisedList) {
  const nodeModulesPath = path.join(projectRoot, 'node_modules');
  
  console.log(`${colors.cyan}Scanning entire dependency tree in node_modules...${colors.reset}\n`);
  
  const allPackages = getAllInstalledPackages(nodeModulesPath);
  
  console.log(`${colors.blue}Found ${allPackages.size} installed packages (including transitive dependencies)${colors.reset}\n`);
  
  const results = {
    compromised: [],
    suspicious: [],
    safe: 0,
    totalScanned: allPackages.size
  };
  
  for (const [name, info] of allPackages) {
    const compromisedData = compromisedList.get(name);
    
    if (compromisedData) {
      const allVersions = Array.from(compromisedData.versions.keys());
      const sources = compromisedData.versions.get(info.version);
      
      if (sources) {
        // Exact version match - COMPROMISED
        results.compromised.push({
          name,
          installedVersion: info.version,
          compromisedVersions: allVersions,
          sources: Array.from(sources),
          allSources: Array.from(compromisedData.sources),
          path: info.path
        });
      } else {
        // Package name matches but different version - SUSPICIOUS
        results.suspicious.push({
          name,
          installedVersion: info.version,
          compromisedVersions: allVersions,
          sources: Array.from(compromisedData.sources),
          path: info.path
        });
      }
    } else {
      results.safe++;
    }
  }
  
  return results;
}

function printResults(results) {
  console.log('='.repeat(80));
  console.log(`${colors.bold}${colors.magenta}DEEP SCAN RESULTS${colors.reset}`);
  console.log('='.repeat(80) + '\n');
  
  console.log(`Total packages scanned: ${colors.cyan}${results.totalScanned}${colors.reset} (including all transitive dependencies)\n`);
  
  if (results.compromised.length > 0) {
    console.log(`${colors.red}${colors.bold}⚠ COMPROMISED PACKAGES DETECTED! (${results.compromised.length})${colors.reset}\n`);
    
    results.compromised.forEach(pkg => {
      console.log(`${colors.red}${colors.bold}✗ ${pkg.name}@${pkg.installedVersion}${colors.reset}`);
      console.log(`  Installed: ${colors.red}${pkg.installedVersion}${colors.reset}`);
      console.log(`  Compromised versions: ${pkg.compromisedVersions.join(', ')}`);
      console.log(`  ${colors.bold}Found in sources: ${colors.cyan}${pkg.sources.join(', ')}${colors.reset}`);
      console.log(`  Location: ${pkg.path}`);
      console.log(`  ${colors.yellow}ACTION: This is a CRITICAL security issue!${colors.reset}\n`);
    });
  }
  
  if (results.suspicious.length > 0) {
    console.log(`${colors.yellow}${colors.bold}⚠ SUSPICIOUS PACKAGES (${results.suspicious.length})${colors.reset}\n`);
    
    results.suspicious.forEach(pkg => {
      console.log(`${colors.yellow}⚠ ${pkg.name}@${pkg.installedVersion}${colors.reset}`);
      console.log(`  Installed: ${pkg.installedVersion}`);
      console.log(`  Compromised versions: ${colors.red}${pkg.compromisedVersions.join(', ')}${colors.reset}`);
      console.log(`  ${colors.bold}Sources: ${colors.cyan}${pkg.sources.join(', ')}${colors.reset}`);
      console.log(`  Location: ${pkg.path}`);
      console.log(`  ${colors.cyan}ACTION: Verify this version is safe${colors.reset}\n`);
    });
  }
  
  console.log(`${colors.green}✓ Safe packages: ${results.safe}${colors.reset}\n`);
  
  if (results.compromised.length > 0) {
    console.log(`${colors.red}${colors.bold}CRITICAL: Your project contains compromised packages!${colors.reset}`);
    console.log(`\nRecommended actions:`);
    console.log(`1. ${colors.bold}DELETE node_modules and package-lock.json/yarn.lock${colors.reset}`);
    console.log(`2. Check which package depends on the compromised one:`);
    console.log(`   ${colors.cyan}npm ls <package-name>${colors.reset} or ${colors.cyan}yarn why <package-name>${colors.reset}`);
    console.log(`3. Update or remove the parent package that requires it`);
    console.log(`4. Run ${colors.cyan}npm install${colors.reset} or ${colors.cyan}yarn install${colors.reset} fresh`);
    console.log(`5. Rotate all credentials, API keys, and secrets`);
    console.log(`6. Scan your system for malware`);
    console.log(`7. Review recent deployments for suspicious activity\n`);
  } else if (results.suspicious.length > 0) {
    console.log(`${colors.yellow}WARNING: Some packages have other compromised versions.${colors.reset}`);
    console.log(`Verify you're using safe versions and update if needed.\n`);
  } else {
    console.log(`${colors.green}${colors.bold}✓ No compromised packages detected in dependency tree!${colors.reset}\n`);
  }
}

async function main() {
  console.log(`${colors.bold}${colors.magenta}`);
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║   Shai-Hulud 2.0 Deep Package Scanner                         ║');
  console.log('║   (Scans entire dependency tree)                              ║');
  console.log('╚════════════════════════════════════════════════════════════════╝');
  console.log(colors.reset + '\n');
  
  try {
    const packageJsonPath = process.argv[2] || './package.json';
    const projectRoot = path.dirname(path.resolve(packageJsonPath));
    
    console.log(`${colors.cyan}Scanning: ${packageJsonPath}${colors.reset}\n`);
    
    const compromisedList = await fetchAllCompromisedPackages();
    const results = scanAllPackages(projectRoot, compromisedList);
    
    printResults(results);
    
    process.exit(results.compromised.length > 0 ? 1 : 0);
    
  } catch (err) {
    console.error(`${colors.red}Error: ${err.message}${colors.reset}`);
    console.error(err.stack);
    process.exit(2);
  }
}

if (require.main === module) {
  main();
}

module.exports = { scanAllPackages, fetchAllCompromisedPackages };