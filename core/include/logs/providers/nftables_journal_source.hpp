#pragma once

#include "firewall/firewall.hpp"
#include "logs/log_source.hpp"

namespace Logging {

/**
 * @brief Reads nftables packet-log lines from the host kernel journal.
 *
 * The journal is only read when the active ruleset contains nftables log
 * statements; otherwise the source reports why it has no entries.
 */
class NftablesJournalSource final : public LogSource {
  public:
	/**
	 * @brief Creates a reader that inspects the given firewall's ruleset.
	 * @param firewall Backend whose active ruleset decides availability; it
	 * must outlive this source.
	 */
	explicit NftablesJournalSource(Firewall &firewall);

	LogSourceResult read() override;

  private:
	Firewall &firewall_;
};

} // namespace Logging
