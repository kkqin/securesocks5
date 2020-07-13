#ifndef NETWORK_ACCEPTOR_SSL_H_
#define NETWORK_ACCEPTOR_SSL_H_

#include "secure_socks5.h"
#include "secure_socks5to.h"

namespace network
{

class Acceptor : public asio::ip::tcp::acceptor
{
public:
	Acceptor(asio::io_service& io_service, int port)  //NOLINT
	        : asio::ip::tcp::acceptor(io_service, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port))
	{
	}
};

template <typename Method>
class AcceptorSSL
{
public:
	AcceptorSSL(std::shared_ptr<asio::io_service> io_service,
		int port,
		const std::function<void(std::shared_ptr<Connection>&&)> onAccept)
		: context(asio::ssl::context::tlsv13),
		io_service(io_service),
		acceptor_(*(io_service.get()), port),
		onAccept_(onAccept)
	{
		std::string cert_file = "./data/ssl/s4wss.crt";
		std::string private_key_file = "./data/ssl/s4wss.key";
		context.use_certificate_chain_file(cert_file);
		context.use_private_key_file(private_key_file, asio::ssl::context::pem);

		accept();
	}

	virtual ~AcceptorSSL()
	{
		acceptor_.cancel();
	}

	// Delete copy constructors
	AcceptorSSL(const AcceptorSSL&) = delete;
	AcceptorSSL& operator=(const AcceptorSSL&) = delete;
private:
	void do_prepare() {
	}

	void accept() {
		const auto socksConnect = std::make_shared<Socks5SecuretoImpl<Method>>(*io_service, context);
		acceptor_.async_accept(socksConnect->socket_.lowest_layer(),
			[this, socksConnect](const error_code& errorCode) {
			if (errorCode == asio::error::basic_errors::operation_aborted) {
				return;
			}
			else if (errorCode) {
				DLOG(ERROR) << "Could not accept connection: " << errorCode.message();
			}
			else {
				DLOG(INFO) << "Accepted connection start handshake";
				socksConnect->set_timeout(5);
				socksConnect->socket_.async_handshake(asio::ssl::stream_base::server,
					[this, socksConnect](const error_code& errorCode) {
					socksConnect->cancel_timeout();
					if (!errorCode) {
						onAccept_(socksConnect);
					}
				});
			}

			// Continue to accept new connections
			accept();
		});
	}

	asio::ssl::context context;
	std::shared_ptr<asio::io_service> io_service;
	Acceptor acceptor_;
	std::function<void(std::shared_ptr<Connection>&&)> onAccept_;
};
}
#endif// NETWORK_SRC_ACCEPTOR_SSL_H_
