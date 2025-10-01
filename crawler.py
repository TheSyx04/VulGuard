import requests
from bs4 import BeautifulSoup
import re
import json
import time
from urllib.parse import urljoin
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OpenSSLCommitCrawler:
    def __init__(self, base_url="https://openssl-library.org/news/vulnerabilities/index.html"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.commit_pattern = re.compile(r'https://github\.com/openssl/openssl/commit/[a-f0-9]+')
        
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
            # Check if the href matches the GitHub commit pattern
            if self.commit_pattern.match(href):
                commit_links.add(href)
            # Also check if it's a relative URL that we need to resolve
            elif 'github.com/openssl/openssl/commit/' in href:
                full_url = urljoin(self.base_url, href)
                if self.commit_pattern.match(full_url):
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
        """Extract commit hashes from GitHub commit URLs."""
        commit_hashes = []
        for link in commit_links:
            # Extract the commit hash from the URL
            match = re.search(r'/commit/([a-f0-9]+)', link)
            if match:
                commit_hashes.append(match.group(1))
        return commit_hashes
    
    def save_results(self, commit_links, output_file='openssl_commits.json'):
        """Save the results to a JSON file."""
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
    
    crawler = OpenSSLCommitCrawler(base_url)
    
    try:
        logger.info("Starting OpenSSL commit crawler...")
        commit_links = crawler.crawl_vulnerability_pages()
        
        logger.info(f"Total unique commit links found: {len(commit_links)}")
        
        # Print the results
        print("\n" + "="*50)
        print("OPENSSL GITHUB COMMIT LINKS FOUND:")
        print("="*50)
        for link in sorted(commit_links):
            print(link)
        
        # Save results
        results = crawler.save_results(commit_links)
        
        print(f"\nSummary:")
        print(f"- Total commits found: {results['total_commits']}")
        print(f"- Results saved to: openssl_commits.json")
        
    except Exception as e:
        logger.error(f"Crawler failed: {e}")
        raise

if __name__ == "__main__":
    main()