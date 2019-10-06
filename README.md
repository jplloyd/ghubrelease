# ghubrelease

Python wrapper for the portion of the github api that deals with releases.

In order to do anything other than fetching information about public repos,
you will need an authentication token with the appropriate privileges for
the repositories you want to work with.

Call the script with `--help` for usage instructions.

## Requirements

Python3 (>= 3.5) and the `requests` package (which can be installed with pip).

## Examples

```
# Using an alias is recommended for brevity when working with
# a single token/repository combination
alias rel='./ghubrelease.py -a TOKEN_VAR username/project'

# If the creation is successful, the id of the new release will be printed to stdout
id=$(rel create new_tag --draft=true --name="The release name" --body="A brand new draft release")

# Edit an existing release, by id or (if it is not a draft) by tag
rel edit -id $id --name="The better release name" --draft=false --body="Now fully released"

# Delete an existing release, by tag or id
rel delete -tag new_tag

# Asset uploading - 'id assetname' is printed to stdout for each successful upload
rel upload-asset --tag=$release_tag asset-file.txt another-asset-file.txt
rel upload-asset -i $release_id --name=filename-on-server.txt \
    --label="Something easier to read"  asset-file.txt
rel upload-asset --tag=$release_tag --replace asset-file.txt another-asset-file.txt ...

# Asset rotation - delete oldest assets to make space in a rolling release
rel upload-asset --max-assets=12 --id=$release_id asset1.txt asset2.txt asset3.txt

```

