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
        self.realname = self.rule['irc_realname']
        if self.password is not None and 'irc_password' in self.pipeline:
            self.rule['irc_password'] = self.password
        else:
            self.password = 'None'
        self.botnick = 'alertbot'
        self.reactor = irc.client.Reactor()
        self.ssl_factory = irc.connection.Factory(wrapper=ssl.wrap_socket)
        self.start()
    getattr(logging, 'DEBUG')
    logging.basicConfig(level=logging.DEBUG)

    def on_connect(self, connection, event):
        channel = self.channel
        if irc.client.is_channel(channel):
            connection.join(channel)

    def on_join(self, connection, event):
        channel = self.channel
        message = self.msg
        reactor = self.reactor
        if irc.client.is_channel(channel):
            connection.privmsg(channel, message)
            print "Alert message sent."
            logging.info("Message %s passed to IRC channel" % message)
        else:
            connection.reconnect(self)
            self.send_message()
            logging.info("Reconnected; tried to send message again.")
        reactor.process_forever()

    def alert(self, matches):
        msg = ''
        for match in matches:
            msg += str(BasicMatchString(self.rule, match))
            if len(matches) > 1:
                msg += '\n----------------------------------------\n'

        if 'includes' in self.rule:
            msg = self.msg
            inc = matches[0].get(self.rule['includes'])
            if inc:
                msg += '\n %s \n' % (inc)
                logging.info("Including in message: %s" % msg)
                print msg

        while True:
            reactor = self.reactor
            status = self.status
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
                status = c.is_connected()
                if status is True:
                    logging.info("Connected to IRC: %s" % status)
                else:
                    logging.warning("WARNING: Not connected to IRC")
                print "Connected to IRC? %s" % status
                reactor.process_forever()
                logging.info("Running process_forever")
            except Exception as err:
                raise EAException("Error sending alert: {0}".format(err))
                print(sys.exc_info()[1])
                raise SystemExit(1)
                logging.warning("Raised EAException: %s" % err)

    def get_info(self):
        return {'type': 'irc'}
