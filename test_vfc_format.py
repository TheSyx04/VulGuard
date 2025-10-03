#!/usr/bin/env python3
"""
Test script to demonstrate the enhanced VFC format generation with branch filtering.
"""

import json
from crawler import OpenSSLCommitCrawler

def test_enhanced_vfc_format():
    """Test the enhanced VFC format generation with branch filtering."""
    print("Testing Enhanced VFC Format Generation with Branch Filtering...")
    
    # Create crawler instance
    crawler = OpenSSLCommitCrawler()
    
    # Mock API results with various scenarios
    test_api_results = {
        'commits_with_cherry_picks': 3,
        'commits_without_cherry_picks': 2,
        'cherry_pick_references': {
            'abc123def456': ['111aaa', '222bbb', '333ccc'],
            'xyz987uvw654': ['444ddd', '555eee'],
            'fedcba987654': ['666fff']
        },
        'master_branch_cherry_picks': {
            'abc123def456': ['111aaa', '333ccc'],  # Only 2 out of 3 are on master
            'xyz987uvw654': ['444ddd']  # Only 1 out of 2 is on master
        },
        'non_master_cherry_picks': {
            'abc123def456': ['222bbb'],  # This one is on feature branch
            'xyz987uvw654': ['555eee'],  # This one is on develop branch  
            'fedcba987654': ['666fff']   # This one is on release branch
        },
        'cherry_pick_branch_info': {
            '111aaa': {'commit_hash': '111aaa', 'branches': ['master'], 'is_on_master': True},
            '222bbb': {'commit_hash': '222bbb', 'branches': ['feature-branch'], 'is_on_master': False},
            '333ccc': {'commit_hash': '333ccc', 'branches': ['master', 'develop'], 'is_on_master': True},
            '444ddd': {'commit_hash': '444ddd', 'branches': ['master'], 'is_on_master': True},
            '555eee': {'commit_hash': '555eee', 'branches': ['develop'], 'is_on_master': False},
            '666fff': {'commit_hash': '666fff', 'branches': ['release-1.0'], 'is_on_master': False}
        },
        'commits_without_cherry_picks_details': {
            'commit1': {
                'message': 'Regular bug fix without cherry-pick',
                'author': 'Developer 1',
                'date': '2023-01-01T00:00:00Z',
                'url': 'https://github.com/openssl/openssl/commit/commit1'
            },
            'commit2': {
                'message': 'Feature addition',
                'author': 'Developer 2', 
                'date': '2023-01-02T00:00:00Z',
                'url': 'https://github.com/openssl/openssl/commit/commit2'
            }
        },
        'total_cherry_pick_commits': 3  # Only master branch cherry-picks
    }
    
    print("\\n" + "="*60)
    print("GENERATING OUTPUT FILES...")
    print("="*60)
    
    # Generate VFC format (master branch only)
    master_cherry_picks = crawler.save_cherry_pick_commits_jsonl(test_api_results, 'test_vfc_master_only.jsonl')
    
    # Generate commits without cherry-picks
    no_cherry_picks = crawler.save_commits_without_cherry_picks(test_api_results, 'test_no_cherry_picks.json')
    
    # Generate non-master cherry-picks
    non_master = crawler.save_non_master_cherry_picks(test_api_results, 'test_non_master_cherry_picks.json')
    
    print(f"\\n" + "="*60)
    print("RESULTS SUMMARY:")
    print("="*60)
    print(f"Master branch cherry-picks (VFC format): {len(master_cherry_picks)} commits")
    print(f"Commits without cherry-picks: {test_api_results['commits_without_cherry_picks']} commits")
    print(f"Non-master cherry-pick sources: {len(test_api_results['non_master_cherry_picks'])} commits")
    
    print(f"\\n" + "="*60)
    print("MASTER BRANCH CHERRY-PICKS (VFC FORMAT):")
    print("="*60)
    for entry in master_cherry_picks:
        print(json.dumps(entry))
    
    print(f"\\n" + "="*60)
    print("BRANCH FILTERING RESULTS:")
    print("="*60)
    for commit_hash, branch_info in test_api_results['cherry_pick_branch_info'].items():
        status = "MASTER" if branch_info['is_on_master'] else "NON-MASTER"
        branches = ", ".join(branch_info['branches'])
        print(f"{commit_hash}: {status} (branches: {branches})")
    
    print(f"\\n" + "="*60)
    print("OUTPUT FILES CREATED:")
    print("="*60)
    print("1. test_vfc_master_only.jsonl - Master branch cherry-picks (for SZZ)")
    print("2. test_no_cherry_picks.json - Commits without cherry-pick references")
    print("3. test_non_master_cherry_picks.json - Non-master branch cherry-picks")
    
    # Read and display VFC file content
    print(f"\\n" + "="*60)
    print("VFC FILE CONTENT (test_vfc_master_only.jsonl):")
    print("="*60)
    try:
        with open('test_vfc_master_only.jsonl', 'r') as f:
            for line_num, line in enumerate(f, 1):
                print(f"Line {line_num}: {line.strip()}")
    except FileNotFoundError:
        print("VFC file not found - check if generation was successful")

if __name__ == "__main__":
    test_enhanced_vfc_format()