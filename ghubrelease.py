#!/usr/bin/env python3
# Copyright (C) 2019 Jesper Lloyd
# Released under GNU GPL v2+, read the file 'LICENSE' for more information.

import argparse
import json
import os
import re
import random
import requests
import logging

import urllib3

log = logging.getLogger(__file__)


def usetimeout(f):
    """Add instance-specific timeout arg to request method call

    Convenience decorator to avoid repetition, completely
    tied to interfaces of ReleaseManager and requests!
    """
    def wrapper(self, *args, **kwargs):
        d = {"timeout": self.timeout}
        d.update(kwargs)
        response = f(self, *args, **d)
        if response.status_code == 401:
            log.error("401: Authorization failed!")
        elif response.status_code == 403:
            log.error(
                "403: Rate limit exceeded (or repeated authorization failure)"
            )
        elif response.status_code == 404:
            log.error(
                "404: Page not found (or authorization failure)!"
            )
        return response
    return wrapper


class ReleaseManager:

    API_TEMPLATE = "https://api.github.com/repos/{repo_slug}/releases/"

    def __init__(
            self,
            repo_slug,
            release_tag,
            lenient=False,
            timeout=None,
            auth_token=None
    ):
        self.base_url = self.API_TEMPLATE.format(repo_slug=repo_slug)
        self.auth_token = auth_token
        self.release_tag = release_tag
        self.lenient = lenient
        self.timeout = timeout

    @usetimeout
    def get(self, *args, **kwargs):
        return requests.get(*args, **kwargs)

    @usetimeout
    def post(self, *args, **kwargs):
        return requests.post(*args, **kwargs)

    @usetimeout
    def patch(self, *args, **kwargs):
        return requests.patch(*args, **kwargs)

    @usetimeout
    def delete(self, *args, **kwargs):
        return requests.delete(*args, **kwargs)

    def get_headers(self):
        headers = dict()
        if self.auth_token:
            headers["Authorization"] = "token " + self.auth_token
        return headers

    def fetch_release(self):
        """Fetch the release info

        :returns: Returns the release info json data as a dict,
                  or None if the release is not found.
        :rtype: dict | None
        """
        url = self.base_url + "tags/" + self.release_tag
        response = self.get(url, headers=self.get_headers())
        if response.status_code != 200:
            log.error("Failed to fetch release!")
            return None
        return json.loads(response.content.decode())

    def create_release(
            self,
            name=None,
            body=None,
            commitish="master",
            draft_release=False,
            pre_release=True,
            replace=False
    ):
        """Create a new release for the manager's repo/tag combination

        :param name: Name of the release
        :type name: str
        :param body: Contents of release body
        :type body: str
        :param commitish: The commit or branch the release should be based on
        :type commitish: str
        :param draft_release: Whether created release is a draft or not
        :type draft_release: bool
        :param pre_release: Whether or not the release is a prerelease
        :type: bool
        :param replace: If a release already exists for the tag, whether to;
                        delete the existing release before creating the new one;
                        not create a new release and just return False.
        :type replace: bool

        :return: True if the release creation was succesful, False otherwise.
        :rtype: bool
        """
        existing_release = self.fetch_release()
        if existing_release:
            if replace:
                self.delete_release()
            else:
                log.warning(
                    "Release already exists for the tag '{tag}'".format(
                        tag = self.release_tag
                    )
                )
                return False
        url = self.base_url[:-1]
        release_data = {
            "tag_name": self.release_tag,
            "target_commitish": commitish,
            "draft": draft_release,
            "prerelease": pre_release
        }
        if name:
            release_data['name'] = name
        if body:
            release_data['body'] = body
        response = self.post(
            url,
            json=release_data,
            headers=self.get_headers(),
        )
        if response.status_code != 201:
            log.error("Failed to create release!")
            return False
        return True

    def edit_release(
            self,
            tag_name=None,
            name=None,
            body=None,
            commitish=None,
            draft=None,
            prerelease=None
    ):

        """Edit an existing release
        At least one parameter must be supplied, and the release must exist.

        :param tag_name: Change existing tag to this value
        :param name: Change the release name/title to this value
        :param body: Change the contents of the release body to this
        :param commitish: Change what the release points to
        :param draft: Set the draft status of the release
        :param prerelease: Set the prerelease status of the release

        :return: True if the edit is successful, False otherwise
        """
        existing = self.fetch_release()
        if not existing:
            log.error("Release not found, cannot edit!")
            return False
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
            response = self.patch(
                url,
                headers=self.get_headers(),
                json=data
            )
            return response.status_code == 200
        else:
            log.error("No edit parameters supplied!")
            return False

    def delete_release(self, ignore_nonexistent=False):
        """Delete the release if it exists

        :param ignore_nonexistent: Return this if the release does not exist
        :type ignore_nonexistent: bool
        :return: True if the release is deleted successfully. If the release
                 does not exist, return ignore_nonexistent.
        """
        release_info = self.fetch_release()
        if not release_info:
            log.warning("Release not found; nothing deleted!")
            return ignore_nonexistent
        release_id = release_info['id']
        url = self.base_url + "{id}".format(id=release_id)
        response = self.delete(
            url,
            headers=self.get_headers()
        )
        if response.status_code != 204:
            log.error("Failed to delete release!")
        return response.status_code == 204

    def upload_asset(
            self,
            asset_path,
            asset_name=None,
            asset_label=None,
            replace_existing=False,
            max_assets=None
    ):
        """

        :param asset_path: File path to the asset that will be uploaded
        :param asset_name: Name to use instead of the file name (optional)
        :param asset_label: Label to display in the asset list (optional)
        :param replace_existing: Whether to delete older assets with the same
                                 name or just not upload the new asset.
        :param max_assets: Maximum number of assets in a rolling release;
                           if the new asset will exceed this limit, delete the
                           n oldest existing assets (by last-updated date) such
                           that the total #assets <= max_assets.
                           Removal of old assets will only be attempted
                           if the new upload is successful.
        :type max_assets: int (>= 1)

        :return: True if the asset was uploaded, False otherwise
        """
        assert (os.path.exists(asset_path) and os.path.isfile(asset_path))

        if not asset_name:
            asset_name = os.path.basename(asset_path)

        release_info = self.fetch_release()
        if not release_info:
            log.error("Cannot upload without valid release data.")
            return False

        existing = {item['name']: item['id'] for item in release_info['assets']}
        if asset_name in existing and not replace_existing:
            log.warning(
                "Asset named '{name}' already exists, not uploading!".format(
                    name=asset_name
                )
            )
            return False
        elif asset_name in existing:
            # Upload new asset first with random prefix
            longest_asset_name = len(max(existing.keys(), key=len))
            rand_length = max(0, longest_asset_name - len(asset_name) - 2)
            rand_num = int(random.random() * 10**rand_length)
            tmp_name = "tmp" + str(rand_num) + asset_name
            response = self._upload(tmp_name, None, asset_path, release_info)
            if response.status_code == 201:
                new_id = json.loads(response.content.decode())['id']
                del_response = self.delete_asset(existing[asset_name])
                if del_response.status_code == 204:
                    self.edit_asset(
                        new_id, new_name=asset_name, new_label=asset_label
                    )
                else:
                    log.error(
                        "Failed to delete old asset for '{name}'. "
                        "New asset uploaded as {tmp_name} w. id {id}".format(
                            name=asset_name, tmp_name=tmp_name, id=new_id
                        )
                    )
                    return False
        else:
            response = self._upload(
                asset_name, asset_label, asset_path, release_info
            )

        if max_assets:
            self._delete_oldest(max_assets)

        return response.status_code == 201

    def edit_asset(self, asset_id, new_name=None, new_label=None):
        if not (new_name or new_label):
            log.error("No edit parameters supplied")
            return False
        data = dict()
        if new_name:
            data['name'] = new_name
        if new_label:
            data['label'] = new_label

        url = self.base_url + "assets/{id}".format(id=asset_id)
        return self.patch(
            url,
            headers=self.get_headers(),
            json=data
        )

    def _upload(self, asset_name, asset_label, asset_path, release_info):
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
            response = self.post(
                url,
                headers=headers,
                data=f
            )
            if response != 201:
                log.error("Upload of '{path}' failed".format(
                    path=asset_path
                ))
            return response

    def _delete_oldest(self, max_assets):
        info = self.fetch_release()
        assets = sorted(info['assets'], key=lambda a: a['updated_at'])
        if len(assets) > max_assets:
            for a in assets[:len(assets) - max_assets]:
                self.delete_asset(a['id'])


    def delete_asset(self, asset_id):
        """Delete asset with the given id

        :param asset_id:
        :return:
        """
        url = self.base_url + "assets/{id}".format(id=asset_id)
        response = self.delete(
            url,
            headers=self.get_headers(),
        )
        return response.status_code == 204

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


def repo_slug_value(slug):
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
        "repo_slug", type=repo_slug_value, metavar="REPO_SLUG",
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
