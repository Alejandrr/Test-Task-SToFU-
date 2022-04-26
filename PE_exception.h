#ifndef PE_EXCEPTION_H
#define PE_EXCEPTION_H
#include <stdexcept>
class PE_handler_exception :public std::runtime_error
{
public:
	enum exception_id
	{
		unexist_pe_file,
		bad_pe_file,
		bad_dos_header,
		bad_nt_headers,
		bad_opt_header,
		bad_arhitecture,
		path_to_PE_missed
	};
	explicit PE_handler_exception(const char* msg, exception_id id)
		:std::runtime_error(msg), _id(id)
	{}
protected:
	exception_id _id;
};
#endif // !PE_EXCEPTION_H