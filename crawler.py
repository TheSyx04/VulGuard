import requests
from bs4 import BeautifulSoup
import re
import json
import time
from urllib.parse import urljoin
import logging
import os
from typing import List, Dict, Set, Optional

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OpenSSLCommitCrawler:
    def __init__(self, base_url="https://openssl-library.org/news/vulnerabilities/index.html", github_token=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        # Commit patterns for both GitHub and git.openssl.org
        self.github_commit_pattern = re.compile(r'https://github\.com/openssl/openssl/commit/([a-f0-9]+)')
        self.git_openssl_pattern = re.compile(r'https://git\.openssl\.org/gitweb/\?p=openssl\.git;a=commitdiff;h=([a-f0-9]+)')
        
        # GitHub API setup
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')
        self.github_session = requests.Session()
        if self.github_token:
            self.github_session.headers.update({
                'Authorization': f'token {self.github_token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'VulGuard-Crawler/1.0'
            })
        else:
            logger.warning("No GitHub token provided. API rate limits will be lower (60 requests/hour)")
            self.github_session.headers.update({
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'VulGuard-Crawler/1.0'
            })
        
        # Cherry-pick patterns
        self.cherry_pick_patterns = [
            re.compile(r'cherry[- ]pick(?:ed)?\s+from\s+commit\s+([a-f0-9]{7,40})', re.IGNORECASE),
            re.compile(r'cherry[- ]pick(?:ed)?\s+([a-f0-9]{7,40})', re.IGNORECASE),
            re.compile(r'\(cherry\s+picked\s+from\s+commit\s+([a-f0-9]{7,40})\)', re.IGNORECASE),
            re.compile(r'cherry-picked\s+from\s+([a-f0-9]{7,40})', re.IGNORECASE),
            re.compile(r'backport\s+of\s+([a-f0-9]{7,40})', re.IGNORECASE),
            re.compile(r'backported\s+from\s+([a-f0-9]{7,40})', re.IGNORECASE),
        ]
        
    def fetch_page(self, url):
        """Fetch a web page with error handling and retry logic."""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                logger.info(f"Fetching page: {url} (attempt {attempt + 1})")
                response = self.session.get(url, timeout=30)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                logger.warning(f"Attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    logger.error(f"Failed to fetch {url} after {max_retries} attempts")
                    raise
    
    def extract_commit_links(self, html_content):
        """Extract GitHub commit links from HTML content."""
        soup = BeautifulSoup(html_content, 'html.parser')
        commit_links = set()
        
        # Find all links
        for link in soup.find_all('a', href=True):
            href = link['href']
            
            # Check GitHub commit pattern
            github_match = self.github_commit_pattern.search(href)
            if github_match:
                commit_links.add(href)
                continue
                
            # Check git.openssl.org pattern
            git_openssl_match = self.git_openssl_pattern.search(href)
            if git_openssl_match:
                commit_links.add(href)
                continue
                
            # Check if it's a relative URL that we need to resolve
            if 'github.com/openssl/openssl/commit/' in href or 'git.openssl.org/gitweb' in href:
                full_url = urljoin(self.base_url, href)
                if (self.github_commit_pattern.search(full_url) or 
                    self.git_openssl_pattern.search(full_url)):
                    commit_links.add(full_url)
        
        return list(commit_links)
    
    def crawl_vulnerability_pages(self):
        """Crawl the main vulnerabilities page and any linked vulnerability pages."""
        all_commit_links = set()
        
        try:
            # Fetch the main page
            response = self.fetch_page(self.base_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract commit links from main page
            main_page_commits = self.extract_commit_links(response.text)
            all_commit_links.update(main_page_commits)
            logger.info(f"Found {len(main_page_commits)} commit links on main page")
            
            # Look for links to individual vulnerability pages
            vulnerability_links = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                if 'vulnerabilities' in href and href.endswith('.html'):
                    full_url = urljoin(self.base_url, href)
                    if full_url != self.base_url:  # Avoid re-crawling the main page
                        vulnerability_links.append(full_url)
            
            logger.info(f"Found {len(vulnerability_links)} vulnerability page links")
            
            # Crawl individual vulnerability pages
            for vuln_url in vulnerability_links:
                try:
                    time.sleep(1)  # Be respectful to the server
                    response = self.fetch_page(vuln_url)
                    vuln_commits = self.extract_commit_links(response.text)
                    all_commit_links.update(vuln_commits)
                    logger.info(f"Found {len(vuln_commits)} commit links on {vuln_url}")
                except Exception as e:
                    logger.error(f"Error crawling {vuln_url}: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Error crawling main page: {e}")
            raise
        
        return list(all_commit_links)
    
    def extract_commit_hashes(self, commit_links):
        """Extract commit hashes from GitHub and git.openssl.org commit URLs."""
        commit_hashes = []
        for link in commit_links:
            # Try GitHub pattern first
            github_match = self.github_commit_pattern.search(link)
            if github_match:
                commit_hashes.append(github_match.group(1))
                continue
                
            # Try git.openssl.org pattern
            git_openssl_match = self.git_openssl_pattern.search(link)
            if git_openssl_match:
                commit_hashes.append(git_openssl_match.group(1))
                continue
                
        return commit_hashes
    
    def get_commit_details(self, commit_hash: str) -> Optional[Dict]:
        """Get commit details from GitHub API."""
        url = f"https://api.github.com/repos/openssl/openssl/commits/{commit_hash}"
        
        try:
            response = self.github_session.get(url, timeout=30)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.warning(f"Commit {commit_hash} not found")
                return None
            elif response.status_code == 403:
                logger.error("GitHub API rate limit exceeded")
                return None
            else:
                logger.warning(f"GitHub API returned status {response.status_code} for commit {commit_hash}")
                return None
        except requests.RequestException as e:
            logger.error(f"Error fetching commit {commit_hash}: {e}")
            return None
    
    def get_commit_branch_info(self, commit_hash: str) -> Optional[Dict]:
        """Get branch information for a specific commit by scraping the GitHub commit page."""
        # Construct the GitHub commit page URL
        url = f"https://github.com/openssl/openssl/commit/{commit_hash}"
        
        try:
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                branches = []
                
                # Method 1: Parse JSON data from script tags (most reliable)
                script_tags = soup.find_all('script', type='application/json')
                for script in script_tags:
                    try:
                        script_content = script.get_text(strip=True)
                        if 'defaultBranch' in script_content:
                            import json
                            data = json.loads(script_content)
                            
                            # Look for repository default branch
                            if isinstance(data, dict):
                                repo_info = data.get('payload', {}).get('repo', {})
                                default_branch = repo_info.get('defaultBranch')
                                if default_branch and default_branch not in branches:
                                    branches.append(default_branch)
                                    logger.info(f"Found default branch from JSON: {default_branch}")
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.debug(f"Could not parse script JSON: {e}")
                        continue
                
                # Method 2: Look for the specific branch class mentioned by user
                branch_elements = soup.find_all(class_="mx-1 prc-BranchName-BranchName-jFtg-")
                for elem in branch_elements:
                    branch_text = elem.get_text(strip=True)
                    if branch_text and branch_text not in branches:
                        branches.append(branch_text)
                        logger.info(f"Found branch from class 'mx-1 prc-BranchName-BranchName-jFtg-': {branch_text}")
                
                # Method 3: Look for branch comparison links
                branch_links = soup.find_all('a', href=re.compile(r'/openssl/openssl/compare/'))
                for link in branch_links:
                    href = link.get('href', '')
                    branch_match = re.search(r'/openssl/openssl/compare/([^/\?]+)', href)
                    if branch_match:
                        branch_name = branch_match.group(1)
                        if branch_name not in branches:
                            branches.append(branch_name)
                            logger.info(f"Found branch from compare link: {branch_name}")
                
                # Method 4: Look for other branch-related elements
                branch_patterns = [
                    r'.*[Bb]ranch.*',
                    r'.*prc-BranchName.*',
                    r'.*branch-name.*'
                ]
                
                for pattern in branch_patterns:
                    elements = soup.find_all(class_=re.compile(pattern))
                    for elem in elements:
                        text = elem.get_text(strip=True)
                        if (text and 
                            len(text) < 50 and 
                            text not in branches and
                            not text.startswith('http') and
                            text.lower() in ['master', 'main']):
                            branches.append(text)
                            logger.info(f"Found branch from pattern '{pattern}': {text}")
                
                # Method 5: Search for master/main in page text as fallback
                if not any(b.lower() in ['master', 'main'] for b in branches):
                    page_text = response.text.lower()
                    if '"defaultbranch":"master"' in page_text:
                        branches.append('master')
                        logger.info("Found 'master' branch from page text search")
                    elif '"defaultbranch":"main"' in page_text:
                        branches.append('main')
                        logger.info("Found 'main' branch from page text search")
                    elif 'master' in page_text and len(branches) == 0:
                        # Very conservative fallback - only if no other branches found
                        branches.append('master')
                        logger.info("Added 'master' as fallback branch")
                
                # Clean up and deduplicate branches
                cleaned_branches = []
                for branch in branches:
                    branch = branch.strip()
                    if branch and branch not in cleaned_branches:
                        cleaned_branches.append(branch)
                
                # Check if master/main is among the branches
                is_on_master = any(branch.lower() in ['master', 'main'] for branch in cleaned_branches)
                
                logger.info(f"Final branches for commit {commit_hash}: {cleaned_branches}, is_on_master: {is_on_master}")
                
                return {
                    'commit_hash': commit_hash,
                    'branches': cleaned_branches,
                    'is_on_master': is_on_master
                }
                
            elif response.status_code == 404:
                logger.warning(f"Commit page for {commit_hash} not found")
                return None
            else:
                logger.warning(f"GitHub returned status {response.status_code} for commit {commit_hash} page")
                return None
                
        except requests.RequestException as e:
            logger.error(f"Error fetching commit page for {commit_hash}: {e}")
            return None
    
    def extract_cherry_pick_commits(self, message: str) -> List[str]:
        """Extract cherry-pick commit hashes from commit message."""
        cherry_picks = []
        
        for pattern in self.cherry_pick_patterns:
            matches = pattern.findall(message)
            for match in matches:
                # Ensure we have at least 7 characters for a valid commit hash
                if len(match) >= 7:
                    cherry_picks.append(match)
        
        return list(set(cherry_picks))  # Remove duplicates
    
    def analyze_commits_with_api(self, commit_hashes: List[str]) -> Dict:
        """Analyze commits using GitHub API to find cherry-pick references."""
        results = {
            'total_analyzed': 0,
            'successful_fetches': 0,
            'commits_with_cherry_picks': 0,
            'commits_without_cherry_picks': 0,
            'cherry_pick_references': {},
            'cherry_pick_branch_info': {},
            'master_branch_cherry_picks': {},
            'non_master_cherry_picks': {},
            'commit_details': {},
            'commits_without_cherry_picks_details': {},
            'errors': []
        }
        
        all_cherry_picks = set()
        
        for i, commit_hash in enumerate(commit_hashes):
            results['total_analyzed'] += 1
            
            # Add rate limiting delay
            if i > 0 and i % 30 == 0:  # Every 30 requests
                logger.info(f"Processed {i} commits, taking a break...")
                time.sleep(2)
            
            logger.info(f"Analyzing commit {i+1}/{len(commit_hashes)}: {commit_hash}")
            
            commit_data = self.get_commit_details(commit_hash)
            if not commit_data:
                results['errors'].append(f"Failed to fetch {commit_hash}")
                continue
            
            results['successful_fetches'] += 1
            
            # Extract commit message
            message = commit_data.get('commit', {}).get('message', '')
            author_date = commit_data.get('commit', {}).get('author', {}).get('date', '')
            author_name = commit_data.get('commit', {}).get('author', {}).get('name', '')
            
            # Store commit details
            results['commit_details'][commit_hash] = {
                'message': message,
                'author': author_name,
                'date': author_date,
                'url': f"https://github.com/openssl/openssl/commit/{commit_hash}"
            }
            
            # Look for cherry-pick references
            cherry_picks = self.extract_cherry_pick_commits(message)
            if cherry_picks:
                results['commits_with_cherry_picks'] += 1
                results['cherry_pick_references'][commit_hash] = cherry_picks
                
                # Check branch information for each cherry-pick commit
                master_cherry_picks = []
                non_master_cherry_picks = []
                
                for cp_hash in cherry_picks:
                    branch_info = self.get_commit_branch_info(cp_hash)
                    if branch_info:
                        results['cherry_pick_branch_info'][cp_hash] = branch_info
                        if branch_info['is_on_master']:
                            master_cherry_picks.append(cp_hash)
                        else:
                            non_master_cherry_picks.append(cp_hash)
                    else:
                        # If we can't get branch info, assume it's not on master
                        non_master_cherry_picks.append(cp_hash)
                    
                    time.sleep(0.5)  # Delay between commit page scraping requests
                
                if master_cherry_picks:
                    results['master_branch_cherry_picks'][commit_hash] = master_cherry_picks
                    all_cherry_picks.update(master_cherry_picks)
                    logger.info(f"Found master branch cherry-picks in {commit_hash}: {master_cherry_picks}")
                
                if non_master_cherry_picks:
                    results['non_master_cherry_picks'][commit_hash] = non_master_cherry_picks
                    logger.info(f"Found non-master cherry-picks in {commit_hash}: {non_master_cherry_picks}")
                    
            else:
                # No cherry-pick references found
                results['commits_without_cherry_picks'] += 1
                results['commits_without_cherry_picks_details'][commit_hash] = {
                    'message': message,
                    'author': author_name,
                    'date': author_date,
                    'url': f"https://github.com/openssl/openssl/commit/{commit_hash}"
                }
                logger.info(f"No cherry-pick references found in {commit_hash}")
            
            time.sleep(0.1)  # Small delay between requests
        
        # Add summary of all unique cherry-pick commits found
        results['all_cherry_pick_commits'] = sorted(list(all_cherry_picks))
        results['total_cherry_pick_commits'] = len(all_cherry_picks)
        
        return results
    
    def save_detailed_results(self, commit_links: List[str], api_results: Dict, output_file='openssl_detailed_commits.json'):
        """Save detailed results including API data."""
        commit_hashes = self.extract_commit_hashes(commit_links)
        
        results = {
            'crawl_info': {
                'total_commits_found': len(commit_links),
                'commit_links': sorted(commit_links),
                'commit_hashes': sorted(commit_hashes),
                'crawled_at': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'api_analysis': api_results,
            'summary': {
                'total_commits_crawled': len(commit_links),
                'total_commits_analyzed': api_results['total_analyzed'],
                'successful_api_fetches': api_results['successful_fetches'],
                'commits_with_cherry_picks': api_results['commits_with_cherry_picks'],
                'commits_without_cherry_picks': api_results['commits_without_cherry_picks'],
                'master_branch_cherry_picks': api_results['total_cherry_pick_commits'],
                'non_master_cherry_picks': len(api_results.get('non_master_cherry_picks', {}))
            }
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Detailed results saved to {output_file}")
        return results
    
    def save_cherry_pick_commits_jsonl(self, api_results: Dict, output_file='cherry_pick_commits.jsonl'):
        """Save master branch cherry-pick commits in JSONL format compatible with VulGuard VFC format."""
        cherry_pick_commits = []
        
        # Collect only master branch cherry-pick commits in VFC format
        for source_commit, cherry_picks in api_results['master_branch_cherry_picks'].items():
            for cherry_pick_hash in cherry_picks:
                # VFC format: {"commit_id": "hash", "Repository": "repo_name"}
                cherry_pick_entry = {
                    'commit_id': cherry_pick_hash,
                    'Repository': 'openssl/openssl'
                }
                cherry_pick_commits.append(cherry_pick_entry)
        
        # Remove duplicates by commit_id
        seen = set()
        unique_cherry_picks = []
        for entry in cherry_pick_commits:
            if entry['commit_id'] not in seen:
                seen.add(entry['commit_id'])
                unique_cherry_picks.append(entry)
        
        # Sort by commit_id for consistency
        unique_cherry_picks.sort(key=lambda x: x['commit_id'])
        
        # Save to JSONL file (one JSON object per line)
        with open(output_file, 'w', encoding='utf-8') as f:
            for entry in unique_cherry_picks:
                json.dump(entry, f, ensure_ascii=False)
                f.write('\n')
        
        logger.info(f"Master branch cherry-pick commits saved to JSONL file: {output_file}")
        logger.info(f"Total unique master branch cherry-pick commits saved: {len(unique_cherry_picks)}")
        
        return unique_cherry_picks
    
    def save_commits_without_cherry_picks(self, api_results: Dict, output_file='commits_without_cherry_picks.json'):
        """Save commits that don't have cherry-pick references to a separate JSON file."""
        commits_data = {
            'total_commits': api_results['commits_without_cherry_picks'],
            'commits': api_results['commits_without_cherry_picks_details'],
            'extracted_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(commits_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Commits without cherry-picks saved to: {output_file}")
        logger.info(f"Total commits without cherry-picks: {api_results['commits_without_cherry_picks']}")
        
        return commits_data
    
    def save_non_master_cherry_picks(self, api_results: Dict, output_file='non_master_cherry_picks.json'):
        """Save cherry-pick commits that are not on master branch to a separate JSON file."""
        # Transform cherry_pick_references to include direct links
        cherry_pick_references_with_links = {}
        
        for source_commit, cherry_picks in api_results['non_master_cherry_picks'].items():
            cherry_pick_references_with_links[source_commit] = []
            for cp_hash in cherry_picks:
                cherry_pick_entry = {
                    'commit_hash': cp_hash,
                    'commit_url': f'https://github.com/openssl/openssl/commit/{cp_hash}'
                }
                cherry_pick_references_with_links[source_commit].append(cherry_pick_entry)
        
        non_master_data = {
            'total_source_commits': len(api_results['non_master_cherry_picks']),
            'cherry_pick_references': cherry_pick_references_with_links,
            'branch_info': api_results['cherry_pick_branch_info'],
            'extracted_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(non_master_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Non-master cherry-pick commits saved to: {output_file}")
        logger.info(f"Total non-master cherry-pick source commits: {len(api_results['non_master_cherry_picks'])}")
        
        return non_master_data
    
    def save_results(self, commit_links, output_file='openssl_commits.json'):
        """Save the basic results to a JSON file."""
        commit_hashes = self.extract_commit_hashes(commit_links)
        
        results = {
            'total_commits': len(commit_links),
            'commit_links': sorted(commit_links),
            'commit_hashes': sorted(commit_hashes),
            'crawled_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Results saved to {output_file}")
        return results

def main():
    """Main function to run the crawler."""
    # Handle the Facebook redirect URL
    base_url = "https://openssl-library.org/news/vulnerabilities/index.html"
    
    # You can set your GitHub token here or as an environment variable
    github_token = os.getenv('GITHUB_TOKEN')  # Set this in your environment variables
    if not github_token:
        logger.warning("No GitHub token found. Consider setting GITHUB_TOKEN environment variable for higher rate limits")
    
    crawler = OpenSSLCommitCrawler(base_url, github_token)
    
    try:
        logger.info("Starting OpenSSL commit crawler...")
        commit_links = crawler.crawl_vulnerability_pages()
        
        logger.info(f"Total unique commit links found: {len(commit_links)}")
        
        # Print the crawled results
        print("\n" + "="*50)
        print("OPENSSL GITHUB COMMIT LINKS FOUND:")
        print("="*50)
        for link in sorted(commit_links):
            print(link)
        
        # Save basic results
        basic_results = crawler.save_results(commit_links)
        
        # Analyze commits with GitHub API
        commit_hashes = crawler.extract_commit_hashes(commit_links)
        logger.info(f"\nStarting GitHub API analysis of {len(commit_hashes)} commits...")
        
        api_results = crawler.analyze_commits_with_api(commit_hashes)
        
        # Save detailed results
        detailed_results = crawler.save_detailed_results(commit_links, api_results)
        
        # Save different types of commits to separate files
        cherry_pick_commits = crawler.save_cherry_pick_commits_jsonl(api_results)
        commits_without_cherry_picks = crawler.save_commits_without_cherry_picks(api_results)
        non_master_cherry_picks = crawler.save_non_master_cherry_picks(api_results)
        
        # Print summary
        print(f"\n" + "="*50)
        print("ANALYSIS SUMMARY:")
        print("="*50)
        print(f"- Total commits crawled: {basic_results['total_commits']}")
        print(f"- Commits analyzed via API: {api_results['successful_fetches']}")
        print(f"- Commits with cherry-pick references: {api_results['commits_with_cherry_picks']}")
        print(f"- Commits without cherry-pick references: {api_results['commits_without_cherry_picks']}")
        print(f"- Master branch cherry-pick commits: {api_results['total_cherry_pick_commits']}")
        print(f"- Non-master cherry-pick source commits: {len(api_results.get('non_master_cherry_picks', {}))}")
        print(f"- Basic results saved to: openssl_commits.json")
        print(f"- Detailed results saved to: openssl_detailed_commits.json")
        print(f"- Master branch cherry-picks saved to: cherry_pick_commits.jsonl (VFC format)")
        print(f"- Commits without cherry-picks saved to: commits_without_cherry_picks.json")
        print(f"- Non-master cherry-picks saved to: non_master_cherry_picks.json")
        
        # Print master branch cherry-pick references
        if api_results['master_branch_cherry_picks']:
            print(f"\n" + "="*50)
            print("MASTER BRANCH CHERRY-PICK REFERENCES:")
            print("="*50)
            for commit, cherry_picks in api_results['master_branch_cherry_picks'].items():
                print(f"Source commit {commit}:")
                for cp in cherry_picks:
                    print(f"  -> Master branch cherry-pick: {cp}")
                print()
        
        # Print non-master cherry-pick references
        if api_results.get('non_master_cherry_picks'):
            print(f"\n" + "="*50)
            print("NON-MASTER CHERRY-PICK REFERENCES:")
            print("="*50)
            for commit, cherry_picks in api_results['non_master_cherry_picks'].items():
                print(f"Source commit {commit}:")
                for cp in cherry_picks:
                    branch_info = api_results['cherry_pick_branch_info'].get(cp, {})
                    branches = branch_info.get('branches', ['unknown'])
                    print(f"  -> Non-master cherry-pick: {cp} (branches: {', '.join(branches)})")
                print()
        
        # Print all unique master branch cherry-pick commits in VFC format
        if api_results['all_cherry_pick_commits']:
            print(f"\n" + "="*50)
            print("VFC-FORMATTED MASTER BRANCH CHERRY-PICK COMMITS:")
            print("="*50)
            for cp_commit in sorted(api_results['all_cherry_pick_commits']):
                vfc_entry = {
                    'commit_id': cp_commit,
                    'Repository': 'openssl/openssl'
                }
                print(json.dumps(vfc_entry))
        
    except Exception as e:
        logger.error(f"Crawler failed: {e}")
        raise

if __name__ == "__main__":
    main()