# -*- coding: utf-8 -*-
import functools
import logging
import socket
import time
import ssl

import irc
from alerts import Alerter
from alerts import BasicMatchString
from irc import client


class IRCAlerter(Alerter):
    '''Connects to an IRC channel, sends alert, and leaves'''
    required_options = frozenset(['irc_server', 'irc_port', 'irc_channel', 'irc_realname'])
    getattr(logging, 'DEBUG')
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-5s [%(name)s] %(message)s')
    logger = logging.getLogger('IRCAlerter')

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
        self.reactor = irc.client.Reactor()
        wrapper = functools.partial(ssl.wrap_socket, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="AES256-SHA")
        self.ssl_factory = irc.connection.Factory(wrapper=wrapper)

    def on_connect(self, connection, event):
        reactor = self.reactor
        channel = self.channel
        self.logger.debug("Recognized channel object - (on_connect)")
        if irc.client.is_channel(channel):
            connection.join(channel)
            self.logger.debug("Joined channel- connection.join(channel)")

    def on_join(self, connection, event):
        channel = self.channel
        # Cannot privmsg newlines, nor longer than some maximum
        message = self.body.replace("\n", " / ")[:200]
        self.logger.debug("Recognized self.body, renamed as message - in on_join")
        reactor = self.reactor
        self.logger.debug("Recognized reactor object - in on_join")
        if irc.client.is_channel(channel):
            connection.privmsg(channel, message)
            self.delivered = True
            print("Alert message sent.")
            self.logger.info("Message %s passed to IRC channel" % message)
        else:
            connection.reconnect()
            self.logger.debug("Connection.reconnect()")
            self.alert()
            self.logger.info("Reconnected; tried to send message again.")

    def on_privmsg(self, connection, event):
        channel = self.channel
        reactor = self.reactor
        self.logger.debug("Recognized reactor object - in on_privmsg")
        if irc.client.is_channel(channel):
            connection.quit(message="I'm out, good luck!")
            self.logger.debug("Disconnected from channel- connection.disconnect_all(message=..)")
            connection.close()

    def alert(self, matches):
        reactor = self.reactor
        self.delivered = False
        self.logger.debug("Recognized body of alert")
        for match in matches:
            self.body += " M:" + str(BasicMatchString(self.rule, match))
            self.logger.debug("Appending matches from rule config to body of alert")
            if len(matches) > 1:
                self.body += "\n"
                self.logger.debug("More to append to message body")
        self.logger.debug("Body: '%s'" % self.body)
        try:
            c = reactor.server().connect(
                self.server,
                self.port,
                self.botnick,
                self.password,
                self.username,
                connect_factory=self.ssl_factory
            )
            self.logger.debug("Adding handlers")
            c.add_global_handler("welcome", self.on_connect)
            self.logger.debug("Added on_connect handler")
            c.add_global_handler("join", self.on_join)
            self.logger.debug("Added on_join handler")
            c.add_global_handler("privmsg", self.on_privmsg)
            self.logger.debug("Added on_privmsg handler")
            status = c.is_connected()
            if status is True:
                self.logger.info("Connected to IRC: %s" % status)
                while not self.delivered:
                    reactor.process_once(0.2)
                reactor.disconnect_all("done")
                reactor.process_once(0.2)
                self.logger.info("Done")
                time.sleep(1)
            else:
                self.logger.warning("WARNING: Not connected to IRC, done")

        except irc.client.ServerConnectionError as x:
            print(x)

    def get_info(self):
        return {'type': 'irc'}
