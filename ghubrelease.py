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


def repo_slug(slug):
    # Only check the basic shape; exactly one '/' with something on both ends.
    if not (
        '/' in slug and
        0 < slug.index('/') < len(slug)-1 and
        slug.index('/') == slug.rindex('/')
    ):
        raise argparse.ArgumentTypeError(
            '"{invalid_slug}" is not a valid repo slug.\n'
            'A repo slug is of the form: "username/repository"'
            ''.format(invalid_slug=slug)
            )
    return slug


def maxassets(value):
    try:
        intval = int(value)
        assert intval > 0
        return intval
    except Exception:
        raise argparse.ArgumentTypeError(
            "The maximum number of assets must be a positive integer."
        )


def get_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "repo_slug", type=repo_slug, metavar="REPO_SLUG",
        help="The 'user/repository' combination of the release"
    )
    parser.add_argument(
        "tag", metavar="TAG_NAME", type=str,
        help="The release tag to operate on"
    )
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument(
        "-a", "--auth-token-var", metavar="VAR_NAME",
        type=envvar_name_check,
        help="The environment variable holding the github auth token",
    )
    auth_group.add_argument(
        "-A", "--auth-token", metavar="TOKEN", type=str,
        help="Pass the github auth token directly (use with caution!)"
    )

    subparsers = parser.add_subparsers(
        title="commands", description="Commands that can be issued",
        dest='command'
    )
    subparsers.required = True

    release_options = argparse.ArgumentParser()
    release_options.add_argument(
        "-t", "--title", metavar="TITLE", type=str,
        help="The release title")
    release_options.add_argument(
        "-b", "--body", metavar="BODY", type=str,
        help="Contents of the release body")
    release_options.add_argument(
        "-c", "--commitish", metavar="COMMITISH", type=str,
        help="Commit/branch of the release - only applies to new ones")
    release_options.add_argument(
        "asset_paths", nargs="*", metavar="FILE", type=filepath_existing,
        help="Filepath of asset that will be added to the release."
    )

    subparsers.add_parser(
        'create', help="Create a new release",
        parents=[release_options], conflict_handler='resolve'
    )
    subparsers.add_parser(
        'delete', help="Delete the release, if it exists."
    )
    subparsers.add_parser(
        'replace', help="Replace an existing release with a new one.",
        parents=[release_options], conflict_handler='resolve'
    )
    parser_rotate = subparsers.add_parser(
        'rotate', help="Upload assets to existing release, "
        "deleting the oldest existing assets to make space if necessary.",
    )
    parser_rotate.add_argument(
        "max_assets", metavar="MAX_ASSETS", type=maxassets)
    parser_rotate.add_argument(
        "asset_paths", metavar="FILE", type=filepath_existing, nargs="+",
        help="Filepath of asset that will be added to the release. "
        "The number of files must be less than or equal to MAX_ASSETS."
    )
    return parser


def verify_token(args):
    """Verify that the given """
    if args.auth_token is not None:
        auth_token = args.auth_token
    else:
        auth_token = os.environ.get(args.auth_token_var)
        if auth_token is None:
            print(
                'The provided auth token environment variable: '
                '"{envvar}" is not defined'.format(
                    envvar=args.auth_token_var
                )
            )
            exit(1)
    if not auth_token:
        print("The auth token cannot be empty!")
        exit(1)
    return auth_token


def create(rm, args):
    return rm.create_release(
        args.title or "Untitled Release",
        args.body or "",
        assets=args.asset_paths,
        commitish=args.commitish or "master"
    )


def main():
    args = get_parser().parse_args()
    auth_token = verify_token(args)
    rm = ReleaseManager(args.repo_slug, args.tag, auth_token)

    if args.command == "create":
        exit(create(rm, args))
    elif args.command == "delete":
        rm.delete_release()
    elif args.command == "replace":
        rm.delete_release()
        create(rm, args)
    elif args.command == "rotate":
        rm.rotate_by_date(args.max_assets, args.asset_paths)

    return args


if __name__ == '__main__':
    exit(main())
