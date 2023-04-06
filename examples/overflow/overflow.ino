/////// Debug construction ///////
#define DEBUG	1
#if DEBUG
#define DPRINT(...)	Serial.print(__VA_ARGS__)
#define DPRINTLN(...)	Serial.println(__VA_ARGS__)
#define DPRINTF(...)	Serial.printf(__VA_ARGS__)
#else
#define DPRINT(...)
#define DPRINTLN(...)
#define DPRINTF(...)
#endif //DEBUG
/////// END Debug construction ///////

#include <WiFi.h>
#include "SPIFFS.h"
/////// SSH //////
#include "libssh_esp32.h"
#include <libssh/libssh.h>
ssh_session my_ssh_session;
int verbosity = SSH_LOG_PROTOCOL;
int port = 22, rc = -1;
/////// SSH //////

void setup() {

#if DEBUG
	Serial.begin( 115200 );
#endif
	WiFi.mode( WIFI_STA );
	WiFi.begin( "YourWiFiSSID", "YourWiFiPSK");
	while ( WiFi.status() != WL_CONNECTED ) {
		DPRINT( F( "." ) );
		delay( 250 );
	}
	DPRINTLN();

	// Initialize SPIFFS
	if ( !SPIFFS.begin() ) {
		DPRINTLN( "An Error has occurred while mounting SPIFFS" );
		SPIFFS.format();
	}

	DPRINT( "IP Address: " );
	DPRINTLN( WiFi.localIP() );

	// Stack size needs to be larger, so continue in a new task.
	xTaskCreatePinnedToCore(controlTask, "ctl", 51200, NULL,
		(tskIDLE_PRIORITY + 3), NULL, portNUM_PROCESSORS - 1);

}

void controlTask(void *pvParameter) {
	while (true) {
#if DEBUG
		if ( Serial.available() > 0 ) {
			serialParse();
		}
#endif

		delay( 10 );
	}
}

void loop() {
	// Nothing to do here since controlTask has taken over.
	vTaskDelay(60000 / portTICK_PERIOD_MS);
}

void serialParse( void ) {

	String str = "";
	char c;
	while ( Serial.available() > 0 ) {
		c = char( Serial.read() );
		if ( ( c != '\n' ) && ( c != '\r' ) ) {
			str += c;
			delay( 2 );
		}
		if ( c == '\n' ) Serial.read();
		if ( c == '\r' ) Serial.read();
	}

	if ( str == "" ) return;
	DPRINTF( "SERIAL INPUT:\t%s\r\n", str.c_str() );

	if ( str == "ssh" ) {
		createConnection();
		return;
	}

	DPRINTLN( F( "INCORRECT INPUT" ) );

}

void createConnection( void ) {

	my_ssh_session = ssh_new();
	if ( my_ssh_session == NULL ) {
		DPRINTLN( "No session" );
		exit( -1 );
	}

	ssh_options_set( my_ssh_session, SSH_OPTIONS_HOST, "192.168.0.222" );
	ssh_options_set( my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity );
	ssh_options_set( my_ssh_session, SSH_OPTIONS_PORT, &port );

	DPRINTLN( "Create session success" );
	DPRINTLN( "Try connect to server" );
	connectToServer( my_ssh_session );
	DPRINTLN( "Connect to server success" );

	DPRINTLN( "Try verify host" );
	verify_knownhost( my_ssh_session );
	DPRINTLN( "Vverify host success" );

	ssh_disconnect( my_ssh_session );
	DPRINTLN( "Disonnect from server success" );
	ssh_free( my_ssh_session );
	DPRINTLN( "Fre resource" );

}

void connectToServer( ssh_session my_ssh_session ) {

	rc = ssh_connect( my_ssh_session );		// <- the controller reboot happens here.
	if ( rc != SSH_OK ) {
		fprintf( stderr, "Error connecting to %s: %s\n",
			"192.168.0.222",
			ssh_get_error( my_ssh_session ) );
		DPRINTLN( "Connect fault." );
		ssh_free( my_ssh_session );
		exit( -1 );
	}

}

int verify_knownhost( ssh_session session ) {

	enum ssh_known_hosts_e state;
	unsigned char* hash = NULL;
	ssh_key srv_pubkey = NULL;
	size_t hlen;

	DPRINTLN( "Get server pub key" );
	rc = ssh_get_server_publickey( session, &srv_pubkey );
	if ( rc < 0 ) {
		return -1;
	}

	DPRINTLN( "Get server pub hash" );
	rc = ssh_get_publickey_hash( srv_pubkey,
				 SSH_PUBLICKEY_HASH_SHA1,
				 &hash,
				 &hlen );
	ssh_key_free( srv_pubkey );

	DPRINTLN( "SSH key free" );
	ssh_key_free( srv_pubkey );
	if ( rc < 0 ) {
		return -1;
	}

	state = ssh_session_is_known_server( session );

	DPRINTF( "State:\t%d\n", state );

	ssh_clean_pubkey_hash( &hash );
	return 0;
}
