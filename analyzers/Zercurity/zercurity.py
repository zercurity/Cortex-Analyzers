#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import logging

from cortexutils.analyzer import Analyzer
from requests_hawk import HawkAuth


class ZercurityException(Exception):
    pass

class ZercurityAnalyzer(Analyzer):

    def __init__(self):

        Analyzer.__init__(self)

        self._url = '{}/v1'.format(self.get_param(
            'config.url',
            'https://api.zercurity.com',
            'Zercurity URL not set'))

        api_id = self.get_param(
            'config.id', None, 'Zercurity API_ID not set')
        api_key = self.get_param(
            'config.key', None, 'Zercurity API_KEY not set')

        self._company = self.get_param(
            'config.company', None)

        self._hawk_auth = HawkAuth(id=api_id, key=api_key)

        self._taxonomies = []


    def get_url(self):
        return self._url


    def get_auth(self):
        return self._hawk_auth


    def get_company_uuid(self):

        # The default company UUID is not provided.
        # Grab the first UUID from the list of companies
        if not self._company:

            companies = requests.get('{}/companies'.format(self.get_url()),
                auth=self.get_auth()).json()

            hits = companies.get('hits', [])

            if not hits:
                raise ZercurityException('API key not assigned to any companies')

            self._company = hits[0].get('uuid')

        return self._company


    def add_taxonomy(self, taxonomy):
        self._taxonomies.append(taxonomy)


    def get_taxonomies(self):
        return self._taxonomies


    def summary(self, raw):
        return dict(
            taxonomies=self.get_taxonomies()
        )


    def run(self):

        company_uuid = self.get_company_uuid()

        if not company_uuid:
            raise ZercurityException('Failed to get company_uuid')

        query = self.get_data()

        assets = []
        discovered = []
        applications = []
        packages = []

        if self.data_type == 'domain':

            # Domains or hostnames can be checked against assets

            assets.extend(self.get_assets(company_uuid, query))

        elif self.data_type == 'ip':

            # If we get an IP address then look through both known assets
            # and discovered assets on the network

            assets.extend(self.get_assets(company_uuid, query))
            discovered.extend(self.get_discovered_assets(
                company_uuid, query))


        elif self.data_type == 'fqdn':

            # FQDN'S can be checked aginst assets in the system

            assets.extend(self.get_assets(company_uuid, query))

        elif self.data_type == 'hash':

            # If we get a hash then look it up against either
            # applications or package hashes that we've seen across
            # assets

            applications.extend(self.get_applications(company_uuid, query))
            packages.extend(self.get_packages(company_uuid, query))


        self.report(dict(
            assets=assets,
            discovered=discovered,
            applications=applications,
            packages=packages
        ))


    def get_assets(self, company_uuid, query):

        assets = requests.get('{}/assets/{}'.format(
            self.get_url(), company_uuid
        ), auth=self.get_auth(), params=dict(
            search=query
        )).json()

        hits = assets.get('hits', [])

        for asset in hits:
            self.add_taxonomy(
                self.build_taxonomy(
                    'INFO', 'ZERCURITY', 'ASSET', '{}, {} ({})'.format(
                        asset.get('name'), asset.get('hostname'),
                        asset.get('risk')
                    )))

        return hits


    def get_discovered_assets(self, company_uuid, query):

        discovered = requests.get('{}/assets/{}/discovered'.format(
            self.get_url(), company_uuid
        ), auth=self.get_auth(), params=dict(
            search=query
        )).json()

        hits = discovered.get('hits', [])

        for asset in hits:
            self.add_taxonomy(
                self.build_taxonomy(
                    'INFO', 'ZERCURITY', 'DISCOVERED', '{}, {} ({})'.format(
                        asset.get('name'), asset.get('vendor'),
                        asset.get('status')
                    )))

        return hits


    def get_applications(self, company_uuid, query):

        application = requests.get('{}/application/{}/{}'.format(
            self.get_url(), company_uuid, query
        ), auth=self.get_auth()).json()

        if application and application.get('sha256'):

            self.add_taxonomy(
                self.build_taxonomy(
                    'INFO', 'ZERCURITY', 'APPLICATION', '{}, {} ({})'.format(
                        application.get('name'), application.get('filename'),
                        application.get('version', 'unknown')
                    )))

            return [application]

        return []


    def get_packages(self, company_uuid, query):

        package = requests.get('{}/package/{}/{}'.format(
            self.get_url(), company_uuid, query
        ), auth=self.get_auth()).json()

        if package and package.get('sha256'):

            self.add_taxonomy(
                self.build_taxonomy(
                    'INFO', 'ZERCURITY', 'PACKAGE', '{}, {} ({})'.format(
                        package.get('name'), package.get('filename'),
                        package.get('version', 'unknown')
                    )))

            return [package]

        return []



if __name__ == '__main__':
    ZercurityAnalyzer().run()
