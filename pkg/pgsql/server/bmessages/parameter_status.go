/*
Copyright 2024 Codenotary Inc. All rights reserved.

SPDX-License-Identifier: BUSL-1.1
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://mariadb.com/bsl11/

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bmessages

import (
	"bytes"
	"encoding/binary"
)

func ParameterStatus(pname, pval []byte) []byte {
	// Identifies the message as a run-time parameter status report.
	messageType := []byte(`S`)
	selfMessageLength := make([]byte, 4)

	//The name of the run-time parameter being reported.
	pname = append(pname, 0)
	// The current value of the parameter.
	pval = append(pval, 0)

	binary.BigEndian.PutUint32(selfMessageLength, uint32(len(pname)+len(pval)+4))
	return bytes.Join([][]byte{messageType, selfMessageLength, pname, pval}, nil)
}
