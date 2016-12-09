service Fetcher
{
    byte FETCH_FROM_URL(1: string url, 2: string digest)
    bool START_STOP()
}
