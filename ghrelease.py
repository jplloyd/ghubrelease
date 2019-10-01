#!/usr/bin/env python3
# Copyright (C) 2019 Jesper Lloyd
# Released under GNU GPL v2+, read the file 'LICENSE' for more information.


import argparse
import json
import os
import re
import requests


class ReleaseManager:

    URL_BASE_TEMPLATE = "https://api.github.com/repos/{repo_slug}/releases/"

    def __init__(
            self,
            repo_slug,
            release_tag,
            auth_token=None
    ):
        self.base_url = self.URL_BASE_TEMPLATE.format(repo_slug=repo_slug)
        self.auth_token = auth_token
        self.release_tag = release_tag
        self.cached_release_info = None

    def get_headers(self):
        headers = dict()
        if self.auth_token:
            headers["Authorization"] = "token " + self.auth_token
        return headers

    def fetch_release(self):
        """Fetch the release info
        Returns the release info as a json object,
        or None if the release is not found.
        """
        if self.cached_release_info:
            return self.cached_release_info
        url = self.base_url + "tags/" + self.release_tag
        response = requests.get(url, headers=self.get_headers())
        if response.status_code != 200:
            self.cached_release_info = None
            return None
        result = json.loads(response.content.decode())
        self.cached_release_info = result
        return result

    def create_release(
            self, title, body,
            assets=None,
            commitish="master",
            draft_release=False
    ):
        """Create a new release"""
        url = self.base_url[:-1]
        release_data = {
            "tag_name": self.release_tag,
            "name": title,
            "target_commitish": commitish,
            "body": body,
            "draft": draft_release,
            "prerelease": True,
        }
        response = requests.post(
            url,
            json=release_data,
            headers=self.get_headers(),
        )
        return response

    def edit_release(
            self, tag_name=None, commitish=None,
            name=None, body=None, draft=None, prerelease=None
    ):
        existing = self.fetch_release()
        if not existing:
            return None
        release_id = existing['id']
        data = dict()
        param_keyvals = {
            "tag_name": tag_name,
            "target_commitish": commitish,
            "name": name,
            "body": body,
            "draft": draft,
            "prerelease": prerelease,
        }
        for k, v in param_keyvals.items():
            if v is not None:
                data[k] = v
        if data:
            url = self.base_url + "{id}".format(id=release_id)
            self.cached_release_info = None
            return requests.patch(
                url,
                headers=self.get_headers(),
                json=data
            )

    def delete_release(self):
        """Delete the release if it exists"""
        release_info = self.fetch_release()
        if not release_info:
            return None
        release_id = release_info['id']
        url = self.base_url + "{id}".format(id=release_id)
        response = requests.delete(
            url,
            headers=self.get_headers()
        )
        self.cached_release_info = None
        return response

    def upload_asset(
            self,
            asset_path,
            asset_name=None,
            asset_label=None
    ):
        assert (os.path.exists(asset_path))
        if not asset_name:
            asset_name = os.path.basename(asset_path)
        release_info = self.fetch_release()
        if release_info:
            url = release_info['upload_url']
            # Strip away the example parameters in braces
            url = url[:url.rindex('{') - len(url)]
            url += "?name={name}".format(name=asset_name)
            if asset_label:
                url += "&label={label}".format(label=asset_label)
            headers = self.get_headers()
            headers['Accept'] = 'application/vnd.github.manifold-preview'
            headers['Content-Type'] = 'application/octet-stream'
            with open(asset_path, "r") as f:
                self.cached_release_info = None
                return requests.post(
                    url,
                    headers=headers,
                    data=f
                )

    def delete_asset(self, asset_id):
        url = self.base_url + "assets/{id}".format(id=asset_id)
        self.cached_release_info = None
        return requests.delete(
            url,
            headers=self.get_headers(),
        )

    def rotate_by_date(self, max_assets, new_assets):
        """Upload new assets and remove old assets

        Upload new assets and delete the n oldest
        existing assets such that the number of assets
        in the release does not exceed 'max_assets'
        """
        # Make sure our input is sane before anything is deleted
        assert (0 < len(new_assets) <= max_assets)
        for asset in new_assets:
            path = asset
            assert (os.path.isfile(path) and os.access(path, os.R_OK))

        info = self.fetch_release()
        assert (info is not None)
        old_assets = sorted(info['assets'], key=lambda a: a['updated_at'])
        spaces_left = (max_assets - len(old_assets)) - len(new_assets)

        # Delete the oldest assets if we need to make space
        if spaces_left < 0:
            for asset in old_assets[:0-spaces_left]:
                self.delete_asset(asset['id'])

        for asset in new_assets:
            self.upload_asset(asset)


def filepath_existing(path):
    error = None
    if not os.path.exists(path):
        error = "File does not exist: {path}".format(path=path)
    elif not os.path.isfile(path):
        error = "Not a file: {path}".format(path=path)
    if error:
        raise argparse.ArgumentTypeError(error)
    return path


def envvar_name_check(name):
    match = re.fullmatch("[^0-9=][^=]*", name)
    if not match:
        raise argparse.ArgumentTypeError(
            '"{varname}" is not a valid environment variable name!'.format(
                varname=name
            )
        )
    return name


def main():
    parser = argparse.ArgumentParser()

    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument(
        "-a", "--auth-token-var", metavar="VAR_NAME",
        type=envvar_name_check,
        help="The environment variable holding the github auth token",
    )
    auth_group.add_argument(
        "-A", "--auth-token", metavar="TOKEN", type=str,
        help="Pass the github auth token directly (be careful with logs!)"
    )
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "-r", "--rotate", metavar="MAX_NUM_ASSETS", type=int,
        help="Upload new assets to existing release, "
             "deleting oldest existing ones to make space."
    )
    action_group.add_argument(
        "-R", "--replace", action="store_true",
        help="Delete the release (if it exists) and replace it with a new one."
    )
    parser.add_argument(
        "repo-slug", type=str, metavar="REPO_SLUG",
        help="The 'user/repository' combination of the release"
    )
    parser.add_argument(
        "tag", metavar="TAG_NAME", type=str,
        help="The release tag to operate on"
    )
    parser.add_argument(
        "file_paths", nargs="+", metavar="FILE", type=filepath_existing,
        help="Path to a file to upload as a release asset"
    )
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    exit(main())
