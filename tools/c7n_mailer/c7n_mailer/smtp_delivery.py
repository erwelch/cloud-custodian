# Copyright 2019 Microsoft Corporation
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


import smtplib

import c7n_mailer.utils as utils


class SmtpDelivery(object):

    def __init__(self, config, session, logger):
        self.logger = logger
        smtp_server = config['smtp_server']
        smtp_port = int(config.get('smtp_port', 25))
        smtp_ssl = bool(config.get('smtp_ssl', True))
        smtp_username = config.get('smtp_username')
        smtp_password = utils.decrypt(config, logger, session, 'smtp_password')

        self.logger.info('Opening SMTP connection to server: {}.'.format(smtp_server))
        smtp_connection = smtplib.SMTP(smtp_server, smtp_port)
        if smtp_ssl:
            self.logger.info('Establishing SSL connection for SMTP delivery.')
            smtp_connection.starttls()
            smtp_connection.ehlo()

        if smtp_username or smtp_password:
            try:
                self.logger.info('Logging into SMTP server.')
                smtp_connection.login(smtp_username, smtp_password)
            except Exception as error:
                self.logger.exception('Failed to login to SMTP server with error: {}'.format(error))

        self._smtp_connection = smtp_connection

    def __del__(self):
        self.logger.info('Closing SMTP connection.')
        self._smtp_connection.quit()

    def send_message(self, message, to_addrs):
        self.logger.info('Sending message to SMTP server.')
        try:
            self._smtp_connection.sendmail(message['From'], to_addrs, message.as_string())
        except Exception as error:
            self.logger.exception('Failed to send message with error: {}'.format(error))
