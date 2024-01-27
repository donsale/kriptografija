// KriptografijaProjektni.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "botan_all.h"
#include <cassert>
#include <print>
#include <algorithm>
#include <functional>
#include <numeric>
#include <utility>
#include <tuple>
#include <array>
#include <range/v3/all.hpp>
#include <scn/all.h>
#include <fstream>
#include <ranges>

std::string prompt(const char* prompt) {
	auto result = scn::prompt<std::string>(prompt, "{:[^\n]}")->value();
	std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

	return result;
}

class User {
public:
	User(std::string username, std::string password)
		: username(std::move(username)), password(std::move(password)) {}

	std::string getUsername() const {
		return username;
	}

	std::string getPassword() const {
		return password;
	}

	bool operator==(const User& other) const {
		return username == other.username;
	}

	std::string readHistory() {
		std::string filename{ "history/" + username + "-history.enc"};
		if (std::FILE * stream{ std::fopen(filename.c_str(), "r") })
		{
			auto result = scn::scan<std::string>(stream, "{}");
			auto ciphertext = result->value();

			std::vector<uint8_t> pt = Botan::hex_decode(ciphertext.c_str());

			auto key = getKey();
			auto dec = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);

			auto nonce = prompt("Nonce: ");
			std::vector<uint8_t> iv = Botan::hex_decode(nonce.c_str());

			dec->set_key(key);
			dec->start(iv);

			try {
				dec->finish(pt);
			}
			catch (Botan::Integrity_Failure&) {
				return std::string("Integrity failure.");
			}

			std::string plaintext{ pt.begin(), pt.end() };

			return plaintext;
		}
		return std::string{""};
	}

	void updateHistory(std::string entry) {
		std::string history = readHistory();

		std::string filename{ "history/" + username + "-history.enc" };
		if (std::FILE * stream{ std::fopen(filename.c_str(), "w")})
		{
			auto key = getKey();

			auto enc = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
			enc->set_key(key);

			Botan::AutoSeeded_RNG rng;
			Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());

			std::string plaintext{ history + entry };
			Botan::secure_vector<uint8_t> pt(plaintext.data(), plaintext.data() + plaintext.length());

			enc->start(iv);
			enc->finish(pt);

			std::print(stream, "{}", Botan::hex_encode(pt));
			std::fclose(stream);

			std::println("IV: {}", Botan::hex_encode(iv));
		}
	}

private:
	std::string username;
	std::string password;

	std::array<uint8_t, 32> getKey() {
		const std::string pbkdf_algo = "PBKDF2(SHA-512)";
		auto pbkdf_runtime = std::chrono::milliseconds(300);
		const size_t output_hash = 32;
		const size_t max_pbkdf_mb = 128;
		auto pwd_fam = Botan::PasswordHashFamily::create_or_throw(pbkdf_algo);
		auto pwdhash = pwd_fam->tune(output_hash, pbkdf_runtime, max_pbkdf_mb);
		std::array<uint8_t, 32> salt{};
		std::array<uint8_t, output_hash> key;
		pwdhash->hash(key, password, salt);

		return key;
	}
};

class UserManager {
public:
	UserManager(const std::string& caCertPath, const std::string& caKeyPath, const std::string& crlPath, const std::string& usersPath) 
		: ca(loadCACertificateAndKey(caCertPath, caKeyPath)), crl(loadCRL(crlPath)), usersPath(usersPath) {
		loadUsers();
	}

	void registerUser() {
		// Input username
		auto username = prompt("Enter username: ");

		// Input password
		auto password = prompt("Enter password: ");

		std::println("Generating RSA key");

		//napravi rsa kljuc
		Botan::RSA_PrivateKey pkey(rng, 2048);

		const std::string hash_fn{ "SHA-256" };

		Botan::X509_Cert_Options opts;

		opts.common_name = username;
		opts.country = prompt("Country: ");
		opts.organization = prompt("Organization: ");
		opts.email = prompt("Email: ");

		opts.add_ex_constraint("PKIX.ClientAuth");

		Botan::PKCS10_Request req = Botan::X509::create_cert_req(opts, pkey, hash_fn, rng);

		auto now = std::chrono::system_clock::now();
		auto one_month = now + std::chrono::days(24 * 30);
		Botan::X509_Time start_time(now);
		Botan::X509_Time end_time(one_month);

		Botan::X509_Certificate cert = ca.sign_request(req, rng, start_time, end_time);
	
		std::string encrypted_key = Botan::PKCS8::PEM_encode(pkey, rng, password);
		
		std::string keyFilename{ "user_certs/" + username + ".key" };
		std::string certFilename{ "user_certs/" + username + ".crt" };

		if (std::FILE * stream{ std::fopen(keyFilename.c_str(), "w") })
		{
			std::print(stream, "{}", encrypted_key);
			std::fclose(stream);

			std::println("Key written to: {}", keyFilename);
		}

		if (std::FILE * stream{ std::fopen(certFilename.c_str(), "w") })
		{
			std::print(stream, "{}", cert.PEM_encode());
			std::fclose(stream);

			std::println("Certificate written to: {}", certFilename);
		}

		if (std::FILE * stream{ std::fopen(usersPath.c_str(), "a") })
		{
			auto hash = Botan::argon2_generate_pwhash(password.c_str(), password.size(), rng, 1, 19, 2); //p=1, M=19, t=2 - owasp
			std::print(stream, "\n{} {}", username, hash);
			std::fclose(stream);

			std::println("User registered. ");

			users.push_back(User(username, hash));
		}
	}

	std::optional<User> loginUser() {
		auto certPath = prompt("Enter certificate: ");
		Botan::X509_Certificate cert(certPath);

		Botan::Path_Validation_Restrictions restrictions(false, 80);
		Botan::Certificate_Store_In_Memory store;

		store.add_certificate(ca.ca_certificate());
		store.add_crl(crl);

		Botan::Path_Validation_Result result = Botan::x509_path_validate(cert, restrictions, store);

		std::println("{}", result.result_string());
		if (!result.successful_validation())
			return {};

		//// Input username
		auto username = prompt("Username: ");
		auto password = prompt("Password: ");

		User user(username, password);

		auto it = ranges::find(users, user);

		if (it != users.end() && Botan::argon2_check_pwhash(password.c_str(), password.size(), it->getPassword())
			&& cert.subject_dn().get_first_attribute("CN") == username) {
			std::println("{} {}{}", "You have successfully logged in as", username, "!");

			return user;
		}
		else {
			std::println("Invalid username or password. Please try again.");
		}

		return {};
	}

private:
	Botan::AutoSeeded_RNG rng;
	Botan::X509_CA ca;
	Botan::X509_CRL crl;
	std::string usersPath = "user_certs/users.txt";
	std::vector<User> users;

	Botan::X509_CA loadCACertificateAndKey(const std::string& caCertPath, const std::string& caKeyPath) {
		// Load the CA certificate
		Botan::X509_Certificate ca_cert(caCertPath);

		//// Load the private key
		Botan::DataSource_Stream in(caKeyPath);
		auto ca_key = Botan::PKCS8::load_key(in);

		const std::string hash_fn{ "SHA-256" };

		// Create X509_CA object using the loaded CA certificate and private key
		Botan::X509_CA ca(ca_cert, *ca_key, hash_fn, rng);

		return ca;
	}

	Botan::X509_CRL loadCRL(const std::string& crlPath) {
		Botan::X509_CRL crl(crlPath);
		return crl;
	}

	void loadUsers()
	{
		if (std::FILE * stream{ std::fopen(usersPath.c_str(), "r") })
		{
			while (auto result = scn::scan<std::string>(stream, "{}")) {
				auto username = result->value();
				auto hash = scn::scan<std::string>(stream, "{}")->value();

				users.push_back(User(username, hash));
			}
		}
	}
};

class RailFenceCipher {
private:
	int depth;

public:
	RailFenceCipher(int n) : depth(n) {}

	std::string encrypt(const std::string& plaintext) const {
		auto noWhitespace = plaintext | ranges::views::filter([](char c) { return !std::isspace(c); }) | ranges::to<std::string>();

		auto ciphertext = ranges::views::iota(0)
			| ranges::views::transform([this, noWhitespace](int i) {
			return noWhitespace | ranges::views::drop(i) | ranges::views::stride(2 * (depth - i % (depth - 1) - 1));
				})
			| ranges::views::take(depth)
			| ranges::views::join(' ')
			| ranges::to<std::string>();

		return ciphertext;
	}
};

// Myszkowski Cipher Implementation
class MyszkowskiCipher {
private:
	std::string key;

public:
	MyszkowskiCipher(std::string key) : key(key) {}

	std::string encrypt(const std::string& plaintext) const {
		auto stepsize = ranges::distance(key);

		auto asciiView = key | ranges::views::transform([](char c) {return static_cast<int>(c);});
		auto sorted = asciiView | ranges::to<std::vector>();

		ranges::sort(sorted);
		ranges::unique(sorted);

		auto joinOrder = asciiView | ranges::views::transform([&sorted](int n) {
			return static_cast<int>(ranges::distance(sorted.begin(), ranges::lower_bound(sorted, n)) + 1);
			})
			| std::ranges::to<std::vector>();	

		auto nowhitespace = plaintext | std::views::filter([](char c) { return !std::isspace(c); }) | std::ranges::to<std::string>();

		auto columns = ranges::views::iota(0)
			| ranges::views::transform([stepsize, nowhitespace](int i) {
			return nowhitespace | ranges::views::drop(i) | ranges::views::stride(stepsize);
				})
			| ranges::views::take(stepsize)
			| ranges::to<std::vector<std::string>>();

		auto zip = ranges::views::zip(joinOrder, columns);
		ranges::sort(zip);

		auto chunked_view = zip | ranges::views::chunk_by([](const auto& e1, const auto& e2) {
			return std::get<0>(e1) == std::get<0>(e2);
			});

		auto ciphertext = chunked_view | ranges::views::transform([](auto&& chunk) {
			return chunk | ranges::views::transform([](auto&& pair) {
				return std::get<1>(pair);
				});
			})
			| ranges::views::transform([](auto&& group) {
				std::vector<int> stride{};
				auto join = group
					| ranges::views::transform([&stride](auto&& elem) {
						auto len = std::distance(elem.begin(), elem.end());
						stride.push_back(len);

						return elem;
					})
					| ranges::views::join
					| ranges::to<std::string>();

				auto inter = ranges::views::iota(0)
					| ranges::views::transform([stride, join](int i) {
					return join | ranges::views::drop(i) | ranges::views::stride(stride[0]); //todo razlicite duzine
						})
					| ranges::views::take(stride[0])
					| ranges::views::join
					| ranges::to<std::string>();

				return inter; 
			})
			| ranges::views::join(' ')
			| ranges::to<std::string>();

		return ciphertext;
	}
};


class PlayfairCipher {
private:
	std::string key;

public:
	PlayfairCipher(std::string key) : key(key) {}

	std::string encrypt(const std::string& plaintext) const {

		std::string uniqueKey;
		ranges::for_each(key, [&uniqueKey](char c) {
			if (uniqueKey.find(c) == std::string::npos) {
				uniqueKey.push_back(c);
			}
		});

		auto rest = ranges::views::iota('A')
			| ranges::views::filter([&uniqueKey](char c) {
			return ranges::find(uniqueKey, c) == uniqueKey.end() && c != 'J';
			})
			| ranges::views::take(25 - uniqueKey.length());

		auto concat = ranges::views::concat(uniqueKey, rest);

		std::array<char, 25> matrix{};
		ranges::copy(concat, matrix.begin());

		auto nowhitespace = plaintext | std::views::filter([](char c) { return !std::isspace(c); }) | std::ranges::to<std::string>();

		auto digrams = nowhitespace
			| ranges::views::chunk(2)
			| ranges::views::transform([](auto&& pair) {
				auto len = std::distance(pair.begin(), pair.end());
				if (len == 1)
					return std::string{ pair[0]};
				else
					return  pair[0] == pair[1] ? std::string{ pair[0], 'X', pair[1] } : std::string{ pair[0], pair[1] };
			})
			| ranges::views::join
			| ranges::to<std::string>();

		if (digrams.length() % 2 != 0)
			digrams += 'X';

		auto ciphertext = digrams
			| ranges::views::chunk(2)
			| ranges::views::transform([&matrix](auto&& chunk) {
			std::vector<char> chunkVec = chunk | ranges::to<std::vector<char>>();
				auto firstChar = chunkVec[0];
				auto secondChar = chunkVec[1];

				auto firstPosition = std::distance(matrix.begin(), ranges::find(matrix, firstChar));
				auto secondPosition = std::distance(matrix.begin(), ranges::find(matrix, secondChar));

				auto get = [&matrix](int row, int col) { return matrix[row * 5 + col]; };

				auto firstRow = firstPosition / 5;
				auto firstCol = firstPosition % 5;
				auto secondRow = secondPosition / 5;
				auto secondCol = secondPosition % 5;

				if (firstRow == secondRow) {
					return std::string{
						get(firstRow, (firstCol + 1) % 5),
						get(secondRow, (secondCol + 1) % 5)
					};
				}
				else if (firstCol == secondCol) {
					return std::string{
						get((firstRow + 1) % 5, firstCol),
						get((secondRow + 1) % 5, secondCol)
					};
				}
				else {
					return std::string{
						get(firstRow, secondCol),
						get(secondRow, firstCol)
					};
				}
			})
			| ranges::views::join
			| ranges::to<std::string>();

		return ciphertext;
	}
};

int main()
{
	std::string caCertPath = "ca/ca.crt";
	std::string caKeyPath = "ca/ca.key";
	std::string crlPath = "ca/crl.pem";
	std::string usersPath = "user_certs/users.txt";

	UserManager userManager(caCertPath, caKeyPath, crlPath, usersPath);
	
	std::print("{} \n{} \n{} \n{} \n{} \n", "Welcome!", "Choose an option:", "\t1. Registration", "\t2. Login", "\t0. Exit");

	while (auto result = scn::prompt<int>("Option: ", "{}"))
	{
		auto option = result->value();
		std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

		switch (option) {
		case 1:
			userManager.registerUser();
			break;
		case 2: {
			auto loginResult = userManager.loginUser();

			if (loginResult.has_value())
			{
				auto user = loginResult.value();
				std::print("{} \n{} \n{} \n{} \n{} \n{} \n", "Choose an option:", "\t1. Rail fence", "\t2. Myszkowski", "\t3. Playfair", "\t4. History", "\t5. Logout");
			
				bool logout = false;
				while (auto input = scn::prompt<int>("Option: ", "{}"))
				{
					auto choice = input->value();
					std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

					switch (choice) {
					case 1: {
						auto depth = scn::prompt<int>("Depth: ", "{}")->value();
						std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
						auto plaintext = prompt("Plaintext: ");

						RailFenceCipher cipher(depth);
						auto ciphertext = cipher.encrypt(plaintext);

						std::println("Ciphertext: {}", ciphertext);

						std::string entry = plaintext + " | RailCipher | " + std::to_string(depth) + " | " + ciphertext + "\n";
						user.updateHistory(entry);

						break;
					}
					case 2:
					{
						auto key = prompt("Key: ");
						auto plaintext = prompt("Plaintext: ");

						MyszkowskiCipher cipher(key);
						auto ciphertext = cipher.encrypt(plaintext);

						std::println("Ciphertext: {}", ciphertext);

						std::string entry = plaintext + " | MyszkowskiCipher | " + key + " | " + ciphertext + "\n";
						user.updateHistory(entry);

						break;
					}
					case 3: {
						auto key = prompt("Key: ");
						auto plaintext = prompt("Plaintext: ");

						PlayfairCipher cipher(key);
						auto ciphertext = cipher.encrypt(plaintext);

						std::println("Ciphertext: {}", ciphertext);

						std::string entry = plaintext + " | PlayfairCipher | " + key + " | " + ciphertext + "\n";
						user.updateHistory(entry);

						break;
					} 
					case 4: {
						auto history = user.readHistory();
						std::println("{}", history);
						break;
					}
					case 5:
						logout = true;
						std::println("Logging out.");
						break;
					default:
						std::println("{}", "Nepoznata opcija.");
					}

					if (logout)
						break;
				}
			}
			break;
		}
		case 0:
			return 0;
		default:
			std::println("{}", "Nepoznata opcija.");
		}

	}


	return 0;
}