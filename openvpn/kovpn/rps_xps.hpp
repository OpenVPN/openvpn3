//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2020 OpenVPN Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <string>

#include <openvpn/common/options.hpp>
#include <openvpn/linux/procfs.hpp>

namespace openvpn {

  // these settings are documented in <linux-kernel>/Documentation/networking/scaling.txt
  class Configure_RPS_XPS
  {
  public:
    Configure_RPS_XPS()
    {
    }

    Configure_RPS_XPS(const OptionList& opt)
    {
      rps_cpus = opt.get_default("rps-cpus", 1, 256, rps_cpus);
      rps_flow_cnt = opt.get_default("rps-flow-cnt", 1, 256, rps_flow_cnt);
      xps_cpus = opt.get_default("xps-cpus", 1, 256, xps_cpus);
    }

    void set(const std::string& dev_name, const unsigned int dev_queue_index, Stop* async_stop) const
    {
      // set RPS/XPS on iface
      ProcFS::write_sys(fmt_qfn(dev_name, "rx", dev_queue_index, "rps_cpus"), rps_cpus + '\n', async_stop);
      ProcFS::write_sys(fmt_qfn(dev_name, "rx", dev_queue_index, "rps_flow_cnt"), rps_flow_cnt + '\n', async_stop);
      ProcFS::write_sys(fmt_qfn(dev_name, "tx", dev_queue_index, "xps_cpus"), xps_cpus + '\n', async_stop);
    }

  private:
    static std::string fmt_qfn(const std::string& dev, const std::string& type, int qnum, const std::string& bn)
    {
      std::ostringstream os;
      return "/sys/class/net/" + dev + "/queues/" + type + "-" + std::to_string(qnum) + '/' + bn;
      return os.str();
    }

    // defaults
    std::string rps_cpus{"0"};        // hex
    std::string rps_flow_cnt{"0"};    // dec
    std::string xps_cpus{"0"};        // hex
  };

}
