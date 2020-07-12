#ifndef NETWORK_SECURE_SOCKS5_H_
#define NETWORK_SECURE_SOCKS5_H_

#include "connection.h"

#include <memory>
#include <utility>
#include <chrono>

#include <glog/logging.h>

namespace network {
	template <typename Method>
	class Socks5SecureImpl : public Connection
	{
		template <typename U> friend class AcceptorSSL;
	public:

		template<typename... Args>
		Socks5SecureImpl(Args &&... args)
			: socket_(std::forward<Args>(args)...),
			out_socket_(*network::IOMgr::instance().netIO().get()),
			closing_(false),
			receiveInProgress_(false),
			sendInProgress_(false),
			is_auth(false),
			resolver(*network::IOMgr::instance().netIO().get())
		{
			method_ = std::make_shared<Method>();
		}

		virtual ~Socks5SecureImpl()
		{
			DLOG(WARNING) << __func__ << " dead";
			method_.reset();
			DLOG(WARNING) << __func__
				<< ": called with closing_:" << (closing_ ? "true" : "false")
				<< ", receiveInProgress_:" << (receiveInProgress_ ? "true" : "false")
				<< ", sendInProgress_:" << (sendInProgress_ ? "true" : "false");
		}

		// Delete copy constructors
		Socks5SecureImpl(const Socks5SecureImpl&) = delete;
		Socks5SecureImpl& operator=(const Socks5SecureImpl&) = delete;

		void set_timeout(long seconds)
		{
			if (seconds == 0) {
				timer_ = nullptr;
				return;
			}

			timer_ = std::unique_ptr<asio::steady_timer>(new asio::steady_timer(socket_.get_executor(), std::chrono::seconds(seconds)));
			std::weak_ptr<Connection> self_weak(this->shared_from_this());
			timer_->async_wait([self_weak](const error_code &ec) {
				if (!ec)
				{
					if (auto self = self_weak.lock()) {
						DLOG(INFO) << "time out";
						self->close(true);
					}
				}
			});
		}

		void cancel_timeout()
		{
			if (timer_) {
				error_code ec;
				timer_->cancel(ec);
			}
		}

		void init() override
		{
			method_->m_cnt = shared_from_this();
			read_handshake();
		}

		void close(bool force) override
		{
			if (closing_)
			{
				DLOG(WARNING) << __func__ << "called with shutdown_: true";
				return;
			}

			closing_ = true;

			DLOG(WARNING) << __func__
				<< ": force: " << (force ? "true" : "false")
				<< ", receiveInProgress_:" << (receiveInProgress_ ? "true" : "false")
				<< "sendInProgress_: " << (sendInProgress_ ? "true" : "false");

			// We can close the socket now if either we should force close,
			// or if there are no send in progress (i.e. no queued packets)
			if (force || !sendInProgress_)
			{
				closeSocket();  // Note that this instance might be deleted during this call
			}

			// Else: we should send all queued packets before closing the connection
		}

	private:

		void read_handshake()
		{
			this->set_timeout(method_->timeout());
			receiveInProgress_ = true;
			auto self(shared_from_this());
			asio::async_read( socket_,
				read_buffer,
				asio::transfer_exactly(3),
				[this, self](const error_code& errorCode, std::size_t len) {
					this->cancel_timeout();
					if (errorCode || closing_ || len < 3u) {
						DLOG(ERROR) << __func__
									<< ": errorCode: " << errorCode.message()
									<< " len expect 3u but now: " << len
									<< " closing_: " << (closing_ ? "true" : "false");
						receiveInProgress_ = false;
						closeSocket(); // Note that this instance might be deleted during this call
						return;
					}

					std::istream stream(&read_buffer);
					stream.read((char *)&in_buf[0], 3);
					if(in_buf[0] != 0x05) {
						DLOG(ERROR) << __func__ << " version not support.";
						receiveInProgress_ = false;
						closeSocket();
						return;
					}

					uint8_t num_methods = in_buf[1];
					in_buf[1] = 0xFF;
					for (uint8_t method = 0; method < num_methods; ++method) {
						if (in_buf[2 + method] == 0x00) { 
							in_buf[1] = 0x00; 
							break; 
						}

						if (in_buf[2 + method] == 0x02) {
							in_buf[1] = 0x02;
							is_auth = true;
							break;
						}
					}

					write_handshake();
				}
			);
		}

		void do_auth() {
			auto self(shared_from_this());
			socket_.async_read_some( 
				asio::buffer(in_buf),
				[this, self](const error_code& errorCode, std::size_t len) {
					if (errorCode) {
						DLOG(ERROR) << __func__
							<< ": errorCode: " << errorCode.message();
						closeSocket();
						return;
					}

					is_auth = false;
					std::uint8_t name_long = in_buf[1];
					std::uint8_t passwd_long = in_buf[1 + 1 + name_long];
					auto username = std::string(&in_buf[2], name_long);
					auto passwd = std::string(&in_buf[1 + 1 + name_long + 1], passwd_long);

					if (username != "letus" || passwd != "bebrave")
						in_buf[1] = 0xFF;
					else
						in_buf[1] = 0x00;
					write_handshake();
				});
		}

		void write_handshake() 
		{
			auto self(shared_from_this());
			receiveInProgress_ = false;
			asio::async_write(socket_,
				asio::buffer(in_buf,2),
				[this, self](const error_code& errorCode, std::size_t len) {
					if(errorCode) {
						DLOG(ERROR) << __func__  
									<< ": errorCode: " << errorCode.message();
						closeSocket();
						return;
					}

					if(in_buf[1] == 0xFF) {
						closeSocket();
						return;
					}

					if (is_auth)
						do_auth();
					else					
						read_request();
				});
		}

		void read_request()
		{
			auto self(shared_from_this());
			receiveInProgress_ = true;
			socket_.async_read_some( 
				asio::buffer(in_buf),
				[this, self](const error_code& errorCode, std::size_t len) {
					if (errorCode || closing_) {
						receiveInProgress_ = false;
						DLOG(ERROR) << __func__  
									<< ": errorCode: " << errorCode.message() << "len:" << len;
						closeSocket();
						return;
					}

					if (len < 5 || in_buf[0] != 0x05 || in_buf[1] != 0x01) {
						receiveInProgress_ = false;
						DLOG(ERROR) << __func__ 
									<< " :socks conect requset invaild.";
						closeSocket();
						return;
					}

					uint8_t addr_type = in_buf[3], host_length;

					switch (addr_type)
					{
					case 0x01: // IP V4 addres
						if (len != 10) { return; }
						remote_host_ = asio::ip::address_v4(ntohl(*((uint32_t*)&in_buf[4]))).to_string();
						remote_port_ = std::to_string(ntohs(*((uint16_t*)&in_buf[8])));
						break;
					case 0x03: // DOMAINNAME
						host_length = in_buf[4];
						if (len != (size_t)(5 + host_length + 2)) { return; }
						remote_host_ = std::string(&in_buf[5], host_length);
						remote_port_ = std::to_string(ntohs(*((uint16_t*)&in_buf[5 + host_length])));
						break;
					default:
						break;
					}

					do_resolve();
			});
		}

		void do_resolve() {
			auto self(shared_from_this());
			receiveInProgress_ = false;
			resolver.async_resolve(asio::ip::tcp::resolver::query({ remote_host_, remote_port_ }),
			[this, self](const error_code& errorCode, asio::ip::tcp::resolver::iterator it) {
				if (errorCode) {
					DLOG(ERROR) << "resolve "<< remote_host_ << " error. code:" << errorCode.message();
					closeSocket();
					return;
				}

				do_connect(it);
			});
		}

		void do_connect(asio::ip::tcp::resolver::iterator& it) {
			auto self(shared_from_this());
			out_socket_.async_connect(*it, 
			[this, self](const error_code& errorCode) {
				if(errorCode) {
					DLOG(ERROR) << "connection error." << remote_host_ << ":" << remote_port_;
					closeSocket();
					return;
				}

				DLOG(INFO) << "connected to " << remote_host_ << ":" << remote_port_;
				write_socks5_response();
			});
		}

		void write_socks5_response() {
			auto self(shared_from_this());
				in_buf[0] = 0x05;
				in_buf[1] = 0x00;
				in_buf[2] = 0x00;
				in_buf[3] = 0x01;
				uint32_t realRemoteIP = out_socket_.remote_endpoint().address().to_v4().to_ulong();
				uint16_t realRemoteport = htons(out_socket_.remote_endpoint().port());

				std::memcpy(&in_buf[4], &realRemoteIP, 4);
				std::memcpy(&in_buf[8], &realRemoteport, 2);

				asio::async_write(socket_, asio::buffer(in_buf, 10),
					[this](const error_code& errorCode, std::size_t len) {
						if(errorCode) {
							closeSocket();
							return;
						}
						do_read(3);
				});
		}

		void do_read(int direction) {

			auto self(shared_from_this());
			if (direction & 0x01) {
				receiveInProgress_ = true;
				socket_.async_read_some(asio::buffer(in_buf),
					[this, self](const error_code& errorCode, std::size_t len) {
					if (errorCode) {
						receiveInProgress_ = false;
						DLOG(ERROR) << "do read up error:" << errorCode.message();
						closeSocket();
						return;
					}

					DLOG(INFO) << "--> " << std::to_string(len) << " bytes";
					do_write(1, len);
				});
			}

			if (direction & 0x02) {
				receiveInProgress_ = true;
				out_socket_.async_read_some(asio::buffer(out_buf),
					[this, self](const error_code& errorCode, std::size_t len) {
					if (errorCode) {
						receiveInProgress_ = false;
						DLOG(ERROR) << "do read down error:" << errorCode.message();
						closeSocket();
						return;
					}
					do_write(2, len);
				});
			}

		}

		void do_write(int direction, std::size_t length) {
			auto self(shared_from_this());
			switch (direction) {
			case 1:
				sendInProgress_ = true;
				asio::async_write(out_socket_, asio::buffer(in_buf, length),
					[this, self, direction](const error_code& errorCode, std::size_t len) {
					if (errorCode) {
						sendInProgress_ = false;
						closeSocket();
						return;
					}
					do_read(direction);
				});
				break;

			case 2:
				sendInProgress_ = true;
				asio::async_write(socket_, asio::buffer(out_buf, length),
					[this, self, direction](const error_code& errorCode, std::size_t len) {
					if (errorCode) {
						sendInProgress_ = false;
						closeSocket();
						return;
					}
					do_read(direction);
				});
				break;
			}
		}

		void closeSocket()
		{
			closing_ = true;

			if (socket_.lowest_layer().is_open())
			{
				error_code error;

				socket_.lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both, error);
				if (error)
				{
					DLOG(ERROR) << __func__ << ": in_socket_ could not shutdown socket: " << error.message();
				}
				socket_.lowest_layer().close();
				if (error)
				{
					DLOG(ERROR) << __func__ << ": socket could not close socket: " << error.message();
				}
			}

			if (out_socket_.is_open())
			{
				error_code error;

				out_socket_.shutdown(asio::ip::tcp::socket::shutdown_type::shutdown_both, error);
				if (error)
				{
					DLOG(ERROR) << __func__ << ": in_out_socket_ could not shutdown socket: " << error.message();
				}
				out_socket_.close(error);
				if (error)
				{
					DLOG(ERROR) << __func__ << ": socket could not close socket: " << error.message();
				}
			}

			//if ((!receiveInProgress_ && !sendInProgress_) || (receiveInProgress_ && sendInProgress_))
			{
				socket_.lowest_layer().close(); out_socket_.close();
				// Time to delete this instance
				method_->onDisconnected();
			}
		}

		asio::ssl::stream<asio::ip::tcp::socket> socket_;
		asio::ip::tcp::socket out_socket_;
		std::shared_ptr<Method> method_;
		std::unique_ptr<asio::steady_timer> timer_;

		bool closing_;
		bool receiveInProgress_;
		bool sendInProgress_;
		bool is_auth;

		// I/O Buffers
		asio::streambuf read_buffer; 
		std::array<char, 8192> in_buf;
		std::array<char, 8192> out_buf;
		std::string remote_host_;
		std::string remote_port_;
		asio::ip::tcp::resolver resolver;
	};
}

#endif 
