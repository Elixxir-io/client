#include "textflag.h"

// Throw enables to throw javascript exceptions
TEXT ·Throw(SB), NOSPLIT, $0
  CallImport
  RET
