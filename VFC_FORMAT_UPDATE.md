# VFC Format Update for VulGuard SZZ Integration

## Overview
The `crawler.py` has been updated to generate `cherry_pick_commits.jsonl` in the correct VFC (Vulnerability Fixing Commit) format that is compatible with VulGuard's SZZ algorithm pipeline. It now includes advanced filtering to only include cherry-pick commits that are on the master branch.

## Changes Made

### 1. Updated `save_cherry_pick_commits_jsonl()` Method
**Before:**
```json
{
    "cherry_pick_commit": "hash",
    "cherry_pick_url": "https://github.com/openssl/openssl/commit/hash",
    "source_commit": "source_hash",
    "source_commit_url": "https://github.com/openssl/openssl/commit/source_hash",
    "source_commit_message": "message",
    "source_commit_author": "author",
    "source_commit_date": "date",
    "extracted_at": "timestamp"
}
```

**After (VFC Format with Master Branch Filtering):**
```json
{
    "commit_id": "hash",
    "Repository": "openssl/openssl"
}
```

### 2. New Features

#### Branch Filtering
- **Master Branch Only**: Only cherry-pick commits on master/main branch are saved to VFC file
- **Branch Detection**: Uses GitHub API to check which branches contain each cherry-pick commit
- **Automatic Filtering**: Non-master cherry-picks are excluded from the VFC file

#### Multiple Output Files
- **`cherry_pick_commits.jsonl`**: Master branch cherry-picks in VFC format (for SZZ input)
- **`commits_without_cherry_picks.json`**: Commits that don't have cherry-pick references
- **`non_master_cherry_picks.json`**: Cherry-pick commits not on master branch

### 3. Key Features
- **VFC Compatibility**: Matches the exact format expected by VulGuard's SZZ algorithm
- **Master Branch Filtering**: Only includes commits from master/main branch
- **Comprehensive Tracking**: Separates different types of commits into appropriate files
- **Branch Information**: Tracks which branches contain each cherry-pick commit
- **Deduplication**: Removes duplicate cherry-pick commits automatically
- **Repository Format**: Uses the correct `"openssl/openssl"` repository format
- **Sorting**: Commits are sorted by commit_id for consistency

### 4. Output Files

#### `cherry_pick_commits.jsonl` (VFC Format)
Master branch cherry-pick commits for SZZ processing:
```jsonl
{"commit_id": "abc123", "Repository": "openssl/openssl"}
{"commit_id": "def456", "Repository": "openssl/openssl"}
```

#### `commits_without_cherry_picks.json`
Commits that don't reference cherry-picks:
```json
{
  "total_commits": 150,
  "commits": {
    "commit_hash": {
      "message": "commit message",
      "author": "author name",
      "date": "2023-01-01T00:00:00Z",
      "url": "https://github.com/openssl/openssl/commit/hash"
    }
  },
  "extracted_at": "2025-10-03 12:00:00"
}
```

#### `non_master_cherry_picks.json`
Cherry-pick commits not on master branch:
```json
{
  "total_source_commits": 10,
  "cherry_pick_references": {
    "source_commit": ["cherry_pick1", "cherry_pick2"]
  },
  "branch_info": {
    "cherry_pick1": {
      "commit_hash": "cherry_pick1",
      "branches": ["feature-branch", "develop"],
      "is_on_master": false
    }
  },
  "extracted_at": "2025-10-03 12:00:00"
}
```

### 5. Integration with VulGuard
The generated `cherry_pick_commits.jsonl` file can now be used directly as:
- Input for SZZ algorithm (`-vfc_file` parameter)
- Input for the mining pipeline (`vulguard mining` command)
- Compatible with the expected VFC format in the project
- **Only includes commits from master branch** for better vulnerability analysis

### 6. Usage Example
```bash
# Run the crawler to generate VFC file
python crawler.py

# Use the generated file with VulGuard mining
vulguard mining \
    -dg_save_folder . \
    -mode local \
    -repo_name openssl \
    -repo_path /path/to/openssl \
    -repo_clone_url https://github.com/openssl/openssl.git \
    -repo_language c \
    -szz vszz \
    -vfc_file cherry_pick_commits.jsonl
```

## File Format Specification

### Input to SZZ Algorithm
Each line in `cherry_pick_commits.jsonl` follows this format:
```json
{"commit_id": "commit_hash", "Repository": "repository_name"}
```

### Example Content
```jsonl
{"commit_id": "758754966791c537ea95241438454aa86f91f256", "Repository": "openssl/openssl"}
{"commit_id": "abc123def456789", "Repository": "openssl/openssl"}
{"commit_id": "def456abc789123", "Repository": "openssl/openssl"}
```

## Benefits
1. **Master Branch Focus**: Only includes production-relevant commits
2. **Direct Integration**: No format conversion needed
3. **SZZ Compatible**: Works with all SZZ variants (vszz, bszz, etc.)
4. **Comprehensive Tracking**: All commit types are preserved in separate files
5. **Quality Filtering**: Improves vulnerability analysis accuracy
6. **Automated Processing**: Can be used in automated pipelines
7. **Consistent Format**: Matches VulGuard's internal data structures

## API Usage
The crawler now makes additional GitHub API calls to check branch information:
- Commit details: `/repos/openssl/openssl/commits/{hash}`
- Branch information: `/repos/openssl/openssl/commits/{hash}/branches-where-head`

**Note**: Consider setting a GitHub token for higher rate limits when processing many commits.

## Testing
Use `test_vfc_format.py` to verify the format generation works correctly.