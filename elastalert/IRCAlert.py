#!/usr/bin/env python
from __future__ import absolute_import

import logging
import ssl
import sys
import threading

import irc
import irc.bot
import irc.client
import irc.connection


class IRCAlert(object):

    def __init__(self, server, port, channel, password, realname, msg):
        super(IRCAlert, self).__init__()
        self.server = server
        self.port = port
        self.channel = channel
        self.password = password
        self.username = realname
        self.msg = msg
        self.botnick = 'alertbot'
        self.status = 'False'
        self.reactor = irc.client.Reactor()
        self.ssl_factory = irc.connection.Factory(wrapper=ssl.wrap_socket)
        thread = threading.Thread(target=self.start, args=())
        thread.daemon = True
        thread.start()
    getattr(logging, 'DEBUG')
    logging.basicConfig(level=logging.DEBUG)

    def on_connect(self, connection, event):
        channel = self.channel
        if irc.client.is_channel(channel):
            connection.join(channel)

    def on_join(self, connection, event):
        channel = self.channel
        message = self.msg
        if irc.client.is_channel(channel):
            connection.privmsg(channel, message)
            print "Alert message sent."

    def on_pong(self, connection, event):
        reactor = self.reactor
        reactor.disconnect_all()

    def start(self):
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
                c.add_global_handler("pong", self.on_pong)
                status = c.is_connected()
                if status:
                    logging.info("Connected to IRC: %s" % status)
                else:
                    logging.warning("WARNING: Not connected to IRC")
                print "Connected to IRC? %s" % status
                print str(reactor)
                reactor.process_forever()
                logging.info("Running process_forever, ending thread")
            except irc.client.ServerConnectionError:
                print(sys.exc_info()[1])
                raise SystemExit(1)
                logging.warning("Raised ServerConnectionError: system exit")
