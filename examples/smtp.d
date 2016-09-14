/*
 * Copyright (c) Rory McGuire - 2016
 * License: Apache License Version 2.0, January 2004
 */
import std.stdio;
import state_machine;
struct InboundSmtpState {
    mixin StateMachine!(status, "pending", "connected", "welcome", "helo", "ehlo", "auth", "starttls", "tls", "mail", "rcpt", "data", "datacomplete", "rset", "quit", "closed", "fatal");
    uint status;
    string toString() {
    	return "state: %s".format(this.statusNames[status]);
    }
	// ^^^ state-machine set up

    uint errors; // how many errors have we had on this connection?


    // Keep state here so we can check it in the state-machine
	TCPConnection rawConn;
	TLSStream tlsstream;
	Stream inbound(size_t line=__LINE__) {
		assert(rawConn !is null);
		writeln("get conn...tls?", tlsstream !is null, " line:", line);
		return tlsstream is null ? cast(Stream)rawConn : cast(Stream)tlsstream;
	}
	auto remote() { return rawConn.peerAddress; }
	auto local() { return rawConn.localAddress; }
	TLSContext ctx;

	// NOTE: methods starting with "to" answer true if we're allowed to change to that state
	// so Don't name callbacks here with "to..."...

	@BeforeTransition("connected")
	bool isNewConnection() {
		writeln("transition to connected? pending:", this.pending, " conn:", rawConn !is null);
		return this.pending && rawConn !is null;
	}
	import std.uuid;
	UUID connection_id;
	UUID[] message_ids;
	@AfterTransition("connected")
	void setId() {
		connection_id = randomUUID();
	}
	@BeforeTransition("welcome")
	bool verifyConnection() {
		enforce(inbound, "invalid network connection");
		if (inbound !is null) {
			// do some set up of the connection
			rawConn.readTimeout = 5.minutes;
		}
		// TODO: put max concurrent connections and ip authentication here
		logInfo("connected: remote:%s, local:%s", this.remote, this.local);
		return true;
	}

	@BeforeTransition("welcome")
	bool canWelcome() {
		return this.connected && !welcomed;
	}
	bool welcomed;
	@AfterTransition("welcome")
	void setWelcome() {
		welcomed = true;
	}

	@BeforeTransition("ehlo")
	bool canEhlo() {
		return this.welcomed && !hadHello;
	}
	@BeforeTransition("helo")
	bool canHelo() {
		return this.welcomed && !hadHello;
	}

	bool hadHello;
	@AfterTransition("ehlo")
	@AfterTransition("helo")
	void setHello() {
		hadHello = true;
	}

	bool hadClose;
	@BeforeTransition("closed")
	bool canClose() {
		if (hadClose) return false;
		hadClose = true;
		return true;
	}

	string mailfrom;
	@BeforeTransition("mail")
	bool canMail() {
		return this.hadHello;
	}

	string[] rcptto;
	@BeforeTransition("rcpt")
	bool canRcpt() {
		return mailfrom != "";
	}

	@BeforeTransition("data")
	bool canData() {
		return mailfrom != "" && rcptto.length > 0;
	}

	UUID messageid;
	@AfterTransition("data")
	void hadData() {
		messageid = randomUUID();
		message_ids ~= messageid;
	}
	@BeforeTransition("datacomplete")
	bool canDataComplete() {
		return this.data;
	}
	@AfterTransition("datacomplete")
	void hadDataComplete() {
		messageid = messageid.init;
		hadRset();
	}

	@BeforeTransition("rset")
	bool canRset() {
		return !this.rset;
	}
	@AfterTransition("rset")
	void hadRset() {
		mailfrom = "";
		rcptto.length = 0;
	}

	@BeforeTransition("starttls")
	bool canStartTLS() {
		return this.rset && tlsstream is null;
	}
	@AfterTransition("starttls")
	void resetForTls() {
		hadRset();
	}

	@BeforeTransition("tls")
	bool canTls() {
		return this.starttls && tlsstream !is null;
	}
	@AfterTransition("tls")
	void useTls() {
		hadHello = false;
	}
}
