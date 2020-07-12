#ifndef NETWORK_SRC_SERVER_SSL_IMPL_H_
#define NETWORK_SRC_SERVER_SSL_IMPL_H_

#include "server.h"
#include <memory>
#include <unordered_map>
#include <utility>
#include <list>
#include "acceptor_ssl.h"
#include <glog/logging.h>
#include "mprocess.h"
#include "connection.h"

namespace network {
	template <typename Method>
	class SSLServer : public Server
	{
	public:
		SSLServer(int port,
			const std::function<void(std::shared_ptr<Connection>&&)>& onClientConnected)
			: acceptor_(network::IOMgr::instance().netIO(),
				port,
				onClientConnected)
		{
		}

		// Delete copy constructors
		SSLServer(const SSLServer&) = delete;
		SSLServer& operator=(const SSLServer&) = delete;

	private:
		AcceptorSSL<Method> acceptor_;
	};
}

#endif  
