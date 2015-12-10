# -*- coding: utf-8 -*-
import functools
import ssl
import time

import irc
import irc.client
from alerts import Alerter
from alerts import BasicMatchString
from util import elastalert_logger


class IRCAlerter(Alerter):
    '''Connects to an IRC channel, sends alert, and leaves'''
    required_options = frozenset(['irc_server', 'irc_port', 'irc_channel', 'irc_realname'])

    def __init__(self, *args):
        super(IRCAlerter, self).__init__(*args)
        self.server = str(self.rule['irc_server'])
        self.port = int(self.rule['irc_port'])
        self.channel = str(self.rule['irc_channel'])
        self.username = str(self.rule['irc_realname'])
        try:
            self.password = str(self.rule['irc_password'])
        except:
            self.password = 'None'
        self.botnick = 'alertbot'
        self.body = ''
        self.client = irc.client.IRC()
        wrapper = functools.partial(ssl.wrap_socket, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="AES256-SHA")
        self.ssl_factory = irc.connection.Factory(wrapper=wrapper)

    def on_connect(self, connection, event):
        channel = self.channel
        elastalert_logger.debug('Recognized channel object - (on_connect)')
        if irc.client.is_channel(channel):
            connection.join(channel)
            elastalert_logger.debug('Joined channel- connection.join(channel)')

    def on_join(self, connection, event):
        channel = self.channel
        message = self.body.replace("\n", " / ")[:200]
        elastalert_logger.debug('Recognized self.body, renamed as message - in on_join')
        elastalert_logger.debug('Recognized irc client object - in on_join')
        if irc.client.is_channel(channel):
            connection.privmsg(channel, message)
            self.delivered = True
            print("Alert message sent.")
            elastalert_logger.info('Message %s passed to IRC channel' % message)
        else:
            connection.reconnect()
            elastalert_logger.debug('Connection.reconnect()')
            self.alert()
            elastalert_logger.info('Reconnected; tried to send message again')

    def on_privmsg(self, connection, event):
        channel = self.channel
        elastalert_logger.debug('Recognized irc client object - in on_privmsg')
        if irc.client.is_channel(channel):
            connection.quit(message="I'm out, good luck!")
            elastalert_logger.debug('Disconnected from channel- connection.disconnect_all(message=..)')
            connection.close()

    def alert(self, matches):
        client = self.client
        server = client.server()
        self.delivered = False
        elastalert_logger.debug('Recognized body of alert')
        for match in matches:
            self.body += " M:" + str(BasicMatchString(self.rule, match))
            elastalert_logger.debug('Appending matches from rule config to body of alert')
            if len(matches) > 1:
                self.body += "\n"
                elastalert_logger.debug('More to append to message body')
        elastalert_logger.debug('Body: %s' % self.body)
        try:
            c = server.connect(
                self.server,
                self.port,
                self.botnick,
                self.password,
                self.username,
                connect_factory=self.ssl_factory
            )
            c.add_global_handler("welcome", self.on_connect)
            c.add_global_handler("join", self.on_join)
            c.add_global_handler("privmsg", self.on_privmsg)
            status = c.is_connected()
            if status is True:
                elastalert_logger.info('Alert for %s at %s:' % (self.rule['name'], match[self.rule['timestamp_field']]))
                while not self.delivered:
                    client.process_once(0.2)
                client.disconnect_all("done")
                client.process_once(0.2)
                time.sleep(1)
            else:
                elastalert_logger.warning('WARNING: Not connected to IRC, done')

        except irc.client.ServerConnectionError as x:
            print(x)

    def get_info(self):
        return {'type': 'irc'}
