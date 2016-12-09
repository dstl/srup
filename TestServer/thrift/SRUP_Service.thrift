exception TokenNotFoundException
{
    1: i32 error_code,
    2: string error_description
    3: string token
}

exception SendInitException
{
    1: i32 error_code,
    2: string error_description
}

service SRUP
{
    string SendInit(1: string target, 2: string url, 3: string digest) throws (1: SendInitException error)
    bool SendActivate(1: string token)
    byte GetResp(1: string token) throws (1: TokenNotFoundException error)
}
