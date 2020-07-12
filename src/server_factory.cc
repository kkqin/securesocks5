#include "server_factory.h"
#include "server_ssl.h"

#ifdef USE_STANDALONE_ASIO
#include <asio.hpp>
#else
#include <boost/asio/ssl.hpp>
#endif

namespace network {
	std::unique_ptr<Server> ServerFactory::createServer(int port,
		const Callback& onClientConnected, ServerFactory::SType type)
	{
		if (type == SType::SSOCKSERVER)
			return std::make_unique<SSLServer<MyMethod>>(port, onClientConnected);
		else
			return nullptr;
	}
}
