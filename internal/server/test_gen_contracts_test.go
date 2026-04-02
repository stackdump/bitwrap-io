package server

import (
	"testing"

	"github.com/stackdump/bitwrap-io/solidity"
)

func TestGenERC721Contracts(t *testing.T) {
	srv := testServer(t)
	
	erc721Template := srv.getTemplate("erc721")
	erc721Sol := solidity.Generate(erc721Template.Schema())
	t.Log(erc721Sol)
}
