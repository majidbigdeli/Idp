using System.Collections.Generic;

namespace Manex.Authentication.Dto {
    public class ReturnDto {
        public bool Status { get; set; }
        public List<ErrorDto> ErrorData { get; set; }
        public dynamic Data { get; set; }
    }


}
