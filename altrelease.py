#!/usr/bin/env python3
# Copyright (C) 2019 Jesper Lloyd
# Released under GNU GPL v2+, read the file 'LICENSE' for more information.

import argparse
import json
import os
import pprint
import re
from random import random as rnd
import requests
import logging

import urllib3

log = logging.getLogger(__file__)


def default_params(f):
    """Add instance-specific args to request method call

    Convenience decorator to avoid repetition, completely
    tied to interfaces of ReleaseManager and requests!
    """
    def wrapper(self, *args, **kwargs):
        d = {
            'timeout': self.timeout,
            'Authorization': 'token ' + self.auth_token
        }
        d.update(kwargs)
        return f(self, *args, **d)
    return wrapper


def log_bad_response(response):
    log.error("HTTP status code: {code}".format(code=response.status_code))
    decoded = response.content.decode()
    try:
        log.error(json.loads(decoded)['message'])
    except json.JSONDecodeError:
        log.warning("Response content is not json data")
        log.error(decoded)
    except KeyError:
        log.error(pprint.pformat(json.loads(decoded)))


class ReleaseManager:

    API_URL_TEMPLATE = "https://api.github.com/repos/{repo_slug}/releases/"

    def __init__(
            self, repo_slug, release_tag, auth_token, timeout=None
    ):
        self.base_url = self.API_URL_TEMPLATE.format(repo_slug=repo_slug)
        self.auth_token = auth_token
        self.release_tag = release_tag
        self.timeout = timeout

    @default_params
    def get(self, *args, **kwargs):
        return requests.get(*args, **kwargs)

    @default_params
    def post(self, *args, **kwargs):
        return requests.post(*args, **kwargs)

    @default_params
    def patch(self, *args, **kwargs):
        return requests.patch(*args, **kwargs)

    @default_params
    def delete(self, *args, **kwargs):
        return requests.delete(*args, **kwargs)

    def get_release_data(self, tag=None, silent=False):
        """Fetch the release info

        :param tag: Tag to use instead of self.release_tag
        :type tag: str
        :param silent: Suppress error messages for this function
        :type silent: bool
        :returns: (data dict, http response) if retrieval is successful.
                  (None, http response) if retrieval request is unsuccessful.
        :rtype: (dict | None, requests.Response)
        """
        url = self.base_url + "tags/" + (tag or self.release_tag)
        response = self.get(url)
        if response.status_code != 200:
            if silent:
                log_bad_response(response)
                log.error("Failed to fetch release!")
            info = None
        else:
            info = json.loads(response.content.decode())
        return info, response

    @staticmethod
    def _release_data(
            tag=None, name=None, body=None,
            commitish=None, draft=False, prerelease=True
    ):
        """
        Return release param dict for non-None values

        :rtype: dict
        """
        params = {
            "tag_name": tag,
            "target_commitish": commitish,
            "name": name,
            "body": body,
            "draft": draft,
            "prerelease": prerelease,
        }
        return {k: v for k, v in params.items() if v is not None}

    def create_release(
            self, tag=None, name=None, body=None,
            commitish=None, draft=False, prerelease=True
    ):
        """Create a new release

        :param tag: Name of the release tag, default is self.release_tag
        :type tag: str
        :param name: Name of the release
        :type name: str
        :param body: Contents of release body
        :type body: str
        :param commitish: The commit or branch the release should be based on
        :type commitish: str
        :param draft: Whether created release is a draft or not
        :type draft: bool
        :param prerelease: Whether or not the release is a prerelease
        :type prerelease: bool

        :return: (True, http response) if creation is successful,
                 (False, http response) if creation request is unsuccessful.
                 (False, None) if the release already exists.
        :rtype: (bool, requests.Response | None)
        """
        release_tag = tag or self.release_tag
        info, _ = self.get_release_data(silent=True)
        if info:
            log.warning("Release already exists: " + release_tag)
            return False, None
        release_data = self._release_data(
            tag=release_tag, name=name, body=body, commitish=commitish,
            draft=draft, prerelease=prerelease
        )
        response = self.post(self.base_url[:-1], json=release_data)
        if response.status_code != 201:
            log_bad_response(response)
            log.error("Failed to create release!")
        return response.status_code == 201, response

    def edit_release(
            self, tag=None, name=None, body=None,
            commitish=None, draft=None, prerelease=None
    ):
        """Edit an existing release

        At least one parameter must be supplied, and the release must exist.

        :param tag: Change existing tag to this value
        :param name: Change the release name/title to this value
        :param body: Change the contents of the release body to this
        :param commitish: Change what the release points to
        :param draft: Set the draft status of the release
        :param prerelease: Set the prerelease status of the release

        :return: (True, http response) if edit is successful,
                 (False, http response) if edit request is unsuccessful.
                 (False, None) if no params or if release cannot be accessed
        :rtype: (bool, requests.Response | None)
        """
        data = self._release_data(
            tag=tag, name=name, body=body, commitish=commitish,
            draft=draft, prerelease=prerelease
        )
        if not data:
            log.error("No edit parameters supplied!")
            return False, None
        info, _ = self.get_release_data()
        if not info:
            log.error("Release not found, cannot edit!")
            return False, None
        else:
            response = self.patch(
                self.base_url + "{id}".format(id=info['id']), json=data
            )
            if response.status_code != 200:
                log_bad_response(response)
                log.error("Failed to edit release!")
            return response.status_code == 200, response

    def delete_release(self):
        """Delete the release if it exists

        :return: (True, http response) if deletion is successful.
                 (False, http response) if deletion request is unsuccessful.
                 (False, None) if the release cannot be accessed.
        :rtype: (bool, requests.Response | None)
        """
        info, _ = self.get_release_data()
        if not info:
            log.warning("Release not found; nothing deleted!")
            return False, None
        release_id = info['id']
        response = self.delete(self.base_url + "{id}".format(id=release_id))
        if response.status_code != 204:
            log_bad_response(response)
            log.error("Failed to delete release!")
        return response.status_code == 204, response

    def upload_asset(
            self, asset_path,
            asset_name=None, asset_label=None,
            replace_existing=False, max_assets=None
    ):
        """Upload a single file as a release asset

        Preconditions:
            The asset_path string must be a valid path to an existing file.
            The release must exist.
            An asset with the same name cannot exist in the same release

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

        :return: (True, http response) if asset upload is successful.
                 (False, http response) if asset upload is unsuccessful.
                 (False, None) if preconditions are not met.
        """
        # Check preconditions
        if not os.path.isfile(asset_path):
            log.error("File does not exist: {path}".format(path=asset_path))
            return False, None
        if not asset_name:
            asset_name = os.path.basename(asset_path)
        info, _ = self.get_release_data()
        if not info:
            log.error("Release data could not be retrieved, cannot upload.")
            return False, None

        existing = {a['name']: a['id'] for a in info['assets']}
        if asset_name in existing and not replace_existing:
            log.error(
                "Asset named '{name}' already exists, not uploading!".format(
                    name=asset_name
                )
            )
            return False, None

        elif asset_name in existing:
            # Upload new asset first with random prefix
            while True:
                tmp_name = "tmp" + str(int(rnd()*1e4)) + asset_name
                if tmp_name not in existing:
                    break
            response = self._upload(tmp_name, None, asset_path, info)
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
                asset_name, asset_label, asset_path, info
            )

        if max_assets:
            self._delete_oldest(max_assets)

        return response.status_code == 201

    def edit_asset(self, asset_id, new_name=None, new_label=None):
        """Edit existing asset

        Preconditions:
            At least one of new_name or new_label must be provided

        :param asset_id: Id of asset to modify
        :param new_name: New name of the asset
        :param new_label: New label for the asset
        :return: (True, http response) if the edit is successful
                 (False, http response) if the edit request is unsuccessful
                 (False, None) if preconditions are not met.
        :rtype: (bool, requests.Response|None)
        """
        if not (new_name or new_label):
            log.error("No edit parameters supplied")
            return False, None
        data = {'name': new_name, 'label': new_label}
        response = self.patch(
            self.base_url + "assets/{id}".format(id=asset_id),
            json={k: v for k, v in data.items() if v is not None}
        )
        if response.status_code != 200:
            log_bad_response(response)
            log.error("Failed to edit asset!")
        return response.status_code == 200, response

    def _upload(self, asset_name, asset_label, asset_path, release_info):
        url = release_info['upload_url']
        # Strip away the example parameters in braces
        url = url[:url.rindex('{') - len(url)]
        url += "?name={name}".format(name=asset_name)
        if asset_label:
            url += "&label={label}".format(label=asset_label)
        headers = {
            'Accept': 'application/vnd.github.manifold-preview',
            'Content-Type': 'application/octet-stream',
        }
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
        info, _ = self.get_release_data()
        assets = sorted(info['assets'], key=lambda a: a['updated_at'])
        if len(assets) > max_assets:
            for a in assets[:len(assets) - max_assets]:
                log.info("Deleting asset '{name}'".format(
                    name=a['name']
                ))
                self.delete_asset(a['id'])

    def delete_asset(self, a_id):
        """Delete asset with the given id

        :param a_id: asset id
        :type a_id: int
        :return: (True, http response) if deletion was successful.
                 (False, http response) if deletion was unsuccessful.
        """
        response = self.delete(self.base_url + "assets/{id}".format(id=a_id))
        if response.status_code != 204:
            log_bad_response(response)
            log.error("Failed to delete asset!")
        return response.status_code == 204, response


# Input verification functions

def file_path_value(path):
    error = None
    if not os.path.exists(path):
        error = "File does not exist: {path}"
    elif not os.path.isfile(path):
        error = "Not a file: {path}"
    if error:
        raise argparse.ArgumentTypeError(error.format(path=path))
    return path


def env_name_value(name):
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


def max_assets_value(value):
    try:
        int_value = int(value)
        assert int_value > 0
        return int_value
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
        type=env_name_value,
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

    # Common options for release creation/modification
    release_options = argparse.ArgumentParser()
    release_options.add_argument(
        "-name", "--name", metavar="NAME", type=str,
        help="The name of the release")
    release_options.add_argument(
        "-b", "--body", metavar="BODY", type=str,
        help="Contents of the release body")
    release_options.add_argument(
        "-c", "--commitish", metavar="COMMITISH", type=str,
        help="Commit/branch of the release")
    release_options.add_argument(
        "-f", "--full-release", action='store_true',
        help="Mark release as full release (not prerelease)"
    )
    release_options.add_argument(
        '-d', '--draft', action='store_true',
        help="Mark release as a draft"
    )

    # Create release
    create_parser = subparsers.add_parser(
        'create', help="Create a new release",
        parents=[release_options], conflict_handler='resolve'
    )
    create_parser.add_argument(
        "-r", "--replace", action="store_true",
        help="If there is an existing release for the tag, delete it first."
    )

    # Edit release
    subparsers.add_parser(
        'edit', help="Edit the release, if it exists.",
        parents=[release_options], conflict_handler='resolve'
    )

    # Delete release
    subparsers.add_parser(
        'delete', help="Delete the release, if it exists."
    )

    # Common options for asset/creation modification
    asset_options = argparse.ArgumentParser()
    asset_options.add_argument(
        "-n", "--name", metavar="NAME", type=str,
        help="Asset name (file name when downloading)"
             " - ignored when uploading multiple files"
    )
    asset_options.add_argument(
        "-l", "--label", metavar="LABEL", type=str,
        help="Asset label (the name that is displayed)"
             " - ignored when uploading multiple files"
    )

    # Upload asset
    upload_parser = subparsers.add_parser(
        'upload-asset', help="Upload an asset file to the release",
        parents=[asset_options], conflict_handler='resolve'
    )
    upload_parser.add_argument(
        "-m", "--max-assets", metavar="MAX_ASSETS", type=max_assets_value,
        help="Delete the oldest assets such that this number is not exceeded"
    )
    upload_parser.add_argument(
        "-r", "--replace", action="store_true",
        help="If an asset with the same name already exists, replace it. "
              "Otherwise, nothing is uploaded"
    )
    upload_parser.add_argument(
        "asset_paths", nargs="+", metavar="FILE", type=file_path_value,
        help="File path of asset that will be added to the release."
    )

    # Edit asset
    edit_asset_parser = subparsers.add_parser(
        'edit-asset', help="Edit the name/label of an existing asset",
        parents=[asset_options], conflict_handler='resolve'
    )
    edit_asset_parser.add_argument('asset_id', metavar="ASSET_ID", type=int)

    # Delete asset
    delete_asset_parser = subparsers.add_parser(
        "delete-asset", help="Delete an existing asset"
    )
    delete_asset_parser.add_argument('asset_id', metavar="ASSET_ID", type=int)

    return parser


def verify_token(args):
    """Basic auth token checks"""
    if args.auth_token is not None:
        auth_token = args.auth_token
    else:
        auth_token = os.environ.get(args.auth_token_var)
        if auth_token is None:
            log.error(
                'The provided auth token environment variable: '
                '"{envvar}" is not defined'.format(
                    envvar=args.auth_token_var
                )
            )
            exit(1)
    if not auth_token:
        log.error("The auth token cannot be empty!")
        exit(1)
    return auth_token


def main():
    args = get_parser().parse_args()
    auth_token = verify_token(args)
    rm = ReleaseManager(
            repo_slug=args.repo_slug,
            release_tag=args.tag,
            auth_token=auth_token,
            timeout=60
    )

    cmd = args.command

    if cmd in ["create", "edit"]:
        func = rm.create_release if cmd == "create" else rm.edit_release
        result = func(
            name=args.name,
            body=args.body,
            commitish=args.commitish,
            draft_release=args.draft,
            pre_release=not args.full_release,
            replace=args.replace
        )
    elif cmd == "delete":
        result = rm.delete_release()
    elif cmd == "upload-asset":
        if len(args.asset_paths) == 1:
            rm.upload_asset(
                asset_path=args.asset_paths[0],
                asset_name=args.name,
                asset_label=args.label,
                replace_existing=args.replace,
                max_assets=args.max_assets
            )
        else:
            if args.name or args.label:
                log.warning(
                    "Asset name/label options ignored for multiple files"
                )
            # Remove any duplicates
            paths = set(args.asset_paths)
            for p in paths:
                rm.upload_asset(
                    asset_path=p,
                    replace_existing=args.replace,
                    max_assets=args.max_assets
                )
    elif cmd == "edit-asset":
        result = rm.edit_asset(
            args.asset_id, new_name=args.name, new_label=args.label
        )
        pass
    elif cmd == "delete-asset":
        result = rm.delete_asset(args.asset_id)

    return result


if __name__ == '__main__':
    exit(main())
