# -*- coding: utf-8 -*-
import logging
import ssl
import sys

import irc
from alerts import Alerter
from alerts import BasicMatchString
from util import EAException


class IRCAlerter(Alerter):
    '''Connects to an IRC channel, sends alert, and leaves'''
    required_options = frozenset(['irc_server', 'irc_port', 'irc_channel', 'irc_realname'])

    def __init__(self, *args):
        super(IRCAlerter, self).__init__(*args)
        self.server = self.rule['irc_server']
        self.port = self.rule['irc_port']
        self.channel = self.rule['irc_channel']
        self.username = self.rule['irc_realname']
        try:
            self.password = self.rule['irc_password']
        except:
            self.password = 'None'
        self.botnick = 'alertbot'
        self.body = ''
        self.reactor = irc.client.Reactor()
        self.ssl_factory = irc.connection.Factory(wrapper=ssl.wrap_socket)
    getattr(logging, 'DEBUG')
    logging.basicConfig(level=logging.DEBUG)

    def on_connect(self, connection, event):
        reactor = self.reactor
        channel = self.channel
        if irc.client.is_channel(channel):
            connection.join(channel)
            reactor.process_data()

    def on_join(self, connection, event):
        channel = self.channel
        message = self.body
        reactor = self.reactor
        if irc.client.is_channel(channel):
            connection.privmsg(channel, message)
            print "Alert message sent."
            logging.info("Message %s passed to IRC channel" % message)
        else:
            connection.reconnect(self)
            self.alert()
            logging.info("Reconnected; tried to send message again.")
        reactor.process_data()

    def on_privmsg(self, connection, event):
        channel = self.channel
        reactor = self.reactor
        if irc.client.is_channel(channel):
            connection.disconnect_all(message="I'm out, good luck!")
            reactor.process_data()

    def alert(self, matches):
        body = self.body
        for match in matches:
            body += str(BasicMatchString(self.rule, match))
            if len(matches) > 1:
                body += '\n----------------------------------------\n'
        while True:
            reactor = self.reactor
            try:
                c = reactor.server().connect(
                    self.server,
                    self.port,
                    self.botnick,
                    self.password,
                    self.username,
                    connect_factory=self.ssl_factory,
                )
                c.add_global_handler("welcome", self.on_connect)
                c.add_global_handler("join", self.on_join)
                c.add_global_handler("privmsg", self.on_privmsg)
                status = c.is_connected()
                if status is True:
                    logging.info("Connected to IRC: %s" % status)
                else:
                    logging.warning("WARNING: Not connected to IRC")
                print "Connected to IRC? %s" % status
            except Exception as err:
                raise EAException("Error sending alert: {0}".format(err))
                print(sys.exc_info()[1])
                logging.warning("Raised EAException: %s" % err)
            reactor.process_data()

    def get_info(self):
        return {'type': 'irc'}
