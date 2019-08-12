# 2019 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import jmespath
from jsonschema import validate, exceptions


class Lookup(object):
    RESOURCE_SOURCE = 'resource'

    schema = {
        'type': 'object',
        'properties': {
            'source': {'type': 'string', 'enum': ['resource']},
            'key': {'type': 'string'},
            'default-value': {'oneOf': [
                {'type': 'string'},
                {'type': 'number'},
                {'type': 'boolean'}
            ]}
        },
        'required': ['source', 'key']
    }

    @staticmethod
    def extract(source, data=None):
        if not Lookup.is_lookup(source):
            return source
        else:
            return Lookup.get_value(source, data)

    @staticmethod
    def is_lookup(source):
        if type(source) is not dict:
            return False

        try:
            validate(instance=source, schema=Lookup.schema)
            return True
        except exceptions.ValidationError:
            return False

    @staticmethod
    def get_value(source, data=None):
        if source['source'] == Lookup.RESOURCE_SOURCE:
            return Lookup.get_value_from_resource(source, data)

    @staticmethod
    def get_value_from_resource(source, resource):
        value = jmespath.search(source['key'], resource)

        if value is not None:
            return value
        if not source['default-value']:
            raise Exception('Lookup for key, {}, returned None'.format(source['key']))
        else:
            return source['default-value']
