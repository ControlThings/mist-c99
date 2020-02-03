#ifndef WISH_PORT_CONFIG_H
#define WISH_PORT_CONFIG_H

/** Port-specific config variables */

/** This specifies the size of the receive ring buffer */
#define WISH_PORT_RX_RB_SZ (10*1024)

/** This specifies the maximum number of simultaneous Wish connections
 * */
#define WISH_PORT_CONTEXT_POOL_SZ   10

#ifndef WISH_PORT_RPC_BUFFER_SZ
/** This specifies the maximum size of the buffer where some RPC handlers build the reply (1400) */
#define WISH_PORT_RPC_BUFFER_SZ ( 16*1024 )
#endif

/** If this is defined, include support for the App TCP server */
#define WITH_APP_TCP_SERVER

#ifndef __ANDROID__
/** With this define you get fancy ANSI colored output on the console */
#define WISH_CONSOLE_COLORS
#endif

#define WISH_PORT_WITH_ASSERT

#endif
