// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from sing-box v1.14.4; see internal/boxnet/UPSTREAM.

package dialer

import (
	"github.com/sagernet/sing/common/control"
)

type UDPListener interface {
	UDPListenerControl() (control.Func, bool)
}
