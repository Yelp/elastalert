# -*- coding: utf-8 -*-
import logging
import socket
import ssl

import irc
from irc import client
from alerts import Alerter
from alerts import BasicMatchString


class IRCAlerter(Alerter):
    '''Connects to an IRC channel, sends alert, and leaves'''
    required_options = frozenset(['irc_server', 'irc_port', 'irc_channel', 'irc_realname'])

    def __init__(self, *args):
        super(IRCAlerter, self).__init__(*args)
        self.server = str(self.rule['irc_server'][0])
        self.port = int(self.rule['irc_port'][0])
        self.channel = str(self.rule['irc_channel'])[0]
        self.username = str(self.rule['irc_realname'][0])
        try:
            self.password = str(self.rule['irc_password'][0])
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
        logging.debug("Recognized reactor object - (on_connect)")
        channel = self.channel
        logging.debug("Recognized channel object - (on_connect)")
        if irc.client.is_channel(channel):
            connection.join(channel)
            logging.debug("Joined channel- connection.join(channel)")
            reactor.process_data(self)
            logging.debug("Running reactor.process_data() - in on_connect")

    def on_join(self, connection, event):
        channel = self.channel
        logging.debug("Recognized channel - in on_join")
        message = self.body
        logging.debug("Recognized self.body, renamed as message - in on_join")
        reactor = self.reactor
        logging.debug("Recognized reactor object - in on_join")
        if irc.client.is_channel(channel):
            connection.privmsg(channel, message)
            print "Alert message sent."
            logging.info("Message %s passed to IRC channel" % message)
        else:
            connection.reconnect()
            logging.debug("Connection.reconnect()")
            self.alert()
            logging.info("Reconnected; tried to send message again.")
        reactor.process_data()
        logging.info("Running reactor.process_data() - in on_join")

    def on_privmsg(self, connection, event):
        channel = self.channel
        logging.debug("Recognized channel object - in on_privmsg")
        reactor = self.reactor
        logging.debug("Recognized reactor object - in on_privmsg")
        if irc.client.is_channel(channel):
            connection.disconnect_all(message="I'm out, good luck!")
            logging.debug("Disconnected from channel- connection.disconnect_all(message=..)")
            reactor.process_data()
            logging.debug("Running reactor.process_data() - in on_privmsg")

    def alert(self, matches):
        body = self.body
        logging.debug("Recognized body of alert")
        print type(body)
        print self.port, type(self.port)
        print matches
        print type(matches), "type of matches"
        for match in matches:
            body += str(BasicMatchString(self.rule, match))
            logging.debug("Appending matches from rule config to body of alert")
            print type(body)
            if len(matches) > 1:
                body += '\n----------------------------------------\n'
                logging.debug("More to append to message body")
        print str(body)
        while True:
            reactor = self.reactor
            logging.debug("Recognized reactor object - (alert True loop)")
            try:
                print self.ssl_factory
                c = reactor.server().connect(
                    self.server,
                    self.port,
                    self.botnick,
                    self.password,
                    self.username,
                    connect_factory=self.ssl_factory
                )
                c.add_global_handler("welcome", self.on_connect)
                logging.debug("Added on_connect handler")
                c.add_global_handler("join", self.on_join)
                logging.debug("Added on_join handler")
                c.add_global_handler("privmsg", self.on_privmsg)
                logging.debug("Added on_privmsg handler")
                status = c.is_connected()
                if status is True:
                    logging.info("Connected to IRC: %s" % status)
                else:
                    logging.warning("WARNING: Not connected to IRC")
            except irc.client.ServerConnectionError as x:
                print(x)

    def get_info(self):
        return {'type': 'irc'}
