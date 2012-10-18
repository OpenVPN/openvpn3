//
//  merge.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_OPTIONS_MERGE_H
#define OPENVPN_OPTIONS_MERGE_H

#include <string>
#include <sstream>
#include <vector>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/common/path.hpp>
#include <openvpn/common/file.hpp>

namespace openvpn {

  class ProfileMerge {
    // internal flags
    enum {
      F_MAY_INCLUDE_KEY_DIRECTION = (1<<0),
      F_PKCS12 = (1<<1),
    };

  public:
    // public status values
    enum Status {
      MERGE_SUCCESS,
      MERGE_EXCEPTION,
      MERGE_OVPN_EXT_FAIL,
      MERGE_OVPN_FILE_FAIL,
      MERGE_REF_FAIL,
      MERGE_MULTIPLE_REF_FAIL,
    };

    // merge status
    Status status() const { return status_; }
    const std::string& error() const { return error_; }

    // merge path basename
    const std::string& basename() const { return basename_; }

    // final unified profile
    const std::string& profile_content() const { return profile_content_; }

    // list of all reference paths successfully read
    const std::vector<std::string>& ref_path_list() const { return ref_succeed_list_; }

    // merge status as a string
    const char *status_string() const
    {
      switch (status_)
	{
	case MERGE_SUCCESS:
	  return "MERGE_SUCCESS";
	case MERGE_EXCEPTION:
	  return "MERGE_EXCEPTION";
	case MERGE_OVPN_EXT_FAIL:
	  return "MERGE_OVPN_EXT_FAIL";
	case MERGE_OVPN_FILE_FAIL:
	  return "MERGE_OVPN_FILE_FAIL";
	case MERGE_REF_FAIL:
	  return "MERGE_REF_FAIL";
	case MERGE_MULTIPLE_REF_FAIL:
	  return "MERGE_MULTIPLE_REF_FAIL";
	default:
	  return "MERGE_?";
	}
    }

    ProfileMerge(const std::string& profile_path)
    {
      try {
	status_ = MERGE_SUCCESS;

	// read the profile
	std::string orig_profile_content;
	std::string profile_dir;
	try {
	  profile_dir = path::dirname(profile_path);
	  basename_ = path::basename(profile_path);
	  const std::string ext = path::ext(basename_);
	  if (string::strcasecmp(ext, "ovpn") == 0)
	    {
	      orig_profile_content = read_text_fast(profile_path);
	    }
	  else
	    {
	      status_ = MERGE_OVPN_EXT_FAIL;
	      error_ = basename_;
	      return;
	    }
	}
	catch (const std::exception& e)
	  {
	    status_ = MERGE_OVPN_FILE_FAIL;
	    error_ = e.what();
	    return;
	  }

	// expand the profile
	{
	  std::stringstream in(orig_profile_content);
	  std::string line;
	  int line_num = 0;
	  bool in_multiline = false;
	  bool opaque_multiline = false;
	  Option multiline;

	  profile_content_.reserve(orig_profile_content.length());
	  while (std::getline(in, line))
	    {
	      string::trim_crlf(line);
	      bool echo = true;
	      ++line_num;
	      if (in_multiline)
		{
		  if (OptionList::is_close_tag(line, multiline[0]))
		    {
		      multiline.clear();
		      in_multiline = false;
		      opaque_multiline = false;
		    }
		}
	      else if (!OptionList::ignore_line(line))
		{
		  Option opt = split_by_space<Option, OptionList::Lex, SpaceMatch>(line);
		  if (opt.size())
		    {
		      if (OptionList::is_open_tag(opt[0]) && opt.size() == 1)
			{
			  OptionList::untag_open_tag(opt[0]);
			  multiline = opt;
			  in_multiline = true;
			  unsigned int flags = 0; // not used
			  opaque_multiline = is_fileref_directive(multiline[0], flags);
			}
		      else
			{
			  unsigned int flags = 0;
			  if (!opaque_multiline
			      && opt.size() >= 2
			      && is_fileref_directive(opt[0], flags))
			    {
			      // found a directive referencing a file

			      // get basename of file and make sure that it doesn't
			      // attempt to traverse directories
			      std::string fn = path::basename(opt[1]);
			      if (fn.empty())
				{
				  echo = false;
				  status_ = MERGE_REF_FAIL;
				}
			      else if (!path::is_flat(fn))
				{
				  echo = false;
				  status_ = MERGE_REF_FAIL;
				  error_ = fn;
				  ref_fail_list_.push_back(fn);
				}
			      else
				{
				  std::string path;
				  std::string file_content;
				  bool error = false;
				  try {
				    path = path::join(profile_dir, fn);
				    file_content = read_text_fast(path);
				  }
				  catch (const std::exception& e)
				    {
				      error = true;
				      status_ = MERGE_REF_FAIL;
				      error_ = fn;
				      ref_fail_list_.push_back(fn);
				    }

				  if (!error) // succeeded in reading file?
				    {
				      // don't echo this line, i.e. opt[], instead expand file_content into profile
				      echo = false;

				      // tls-auth or secret directive may include key-direction parameter
				      if ((flags & F_MAY_INCLUDE_KEY_DIRECTION) && opt.size() >= 3)
					{
					  const std::string kd = "key-direction " + opt[2] + "\n";
					  profile_content_ += kd;
					}

				      // format file_content for appending to profile
				      {
					std::ostringstream os;
					string::add_trailing_in_place(file_content, '\n');
					os << '<' << opt[0] << ">\n" << file_content << "</" << opt[0] << ">\n";
					profile_content_ += os.str();
				      }

				      // save file we referenced
				      ref_succeed_list_.push_back(fn);
				    }
				}
			    }
			}
		    }
		}
	      if (echo)
		{
		  profile_content_ += line;
		  profile_content_ += '\n';
		}
	    }

	  // If more than 2 errors occurred, change status to
	  // MERGE_MULTIPLE_REF_FAIL and enumerate each failed file.
	  if (ref_fail_list_.size() >= 2)
	    {
	      status_ = MERGE_MULTIPLE_REF_FAIL;
	      error_ = "";
	      for (size_t i = 0; i < ref_fail_list_.size(); ++i)
		{
		  if (i)
		    error_ += ", ";
		  error_ += ref_fail_list_[i];
		}
	    }
	}
      }
      catch (const std::exception& e)
	{
	  status_ = MERGE_EXCEPTION;
	  error_ = e.what();
	}
    }

  private:
    static bool is_fileref_directive(const std::string& d, unsigned int& flags)
    {
      if (d.length() > 0)
	{
	  switch (d[0])
	    {
	    case 'c':
	      return d == "ca" || d == "cert";
	    case 'd':
	      return d == "dh";
	    case 'e':
	      return d == "extra-certs";
	    case 'k':
	      return d == "key";
#if 0 // define when we have capability to parse out pkcs12 from profile and add to Keychain (fixme)
	    case 'p':
	      if (d == "pkcs12")
		{
		  flags |= F_PKCS12;
		  return true;
		}
	      return false;
#endif
	    case 's':
	      if (d == "secret")
		{
		  flags |= F_MAY_INCLUDE_KEY_DIRECTION;
		  return true;
		}
	      return false;
	    case 't':
	      if (d == "tls-auth")
		{
		  flags |= F_MAY_INCLUDE_KEY_DIRECTION;
		  return true;
		}
	      return false;
	    }
	}
      return false;
    }

    Status status_;
    std::string profile_content_;
    std::string basename_;
    std::string error_;
    std::vector<std::string> ref_fail_list_;
    std::vector<std::string> ref_succeed_list_;
  };
}

#endif
