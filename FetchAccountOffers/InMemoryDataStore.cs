using Google.Apis.Util.Store;
using System.Collections.Concurrent;

public class InMemoryDataStore : IDataStore
{
    private readonly ConcurrentDictionary<string, string> _store = new ConcurrentDictionary<string, string>();

    public Task ClearAsync()
    {
        _store.Clear();
        return Task.CompletedTask;
    }

    public Task DeleteAsync<T>(string key)
    {
        _store.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    public Task<T> GetAsync<T>(string key)
    {
        if (_store.TryGetValue(key, out string value))
        {
            return Task.FromResult(Newtonsoft.Json.JsonConvert.DeserializeObject<T>(value));
        }
        return Task.FromResult(default(T));
    }

    public Task StoreAsync<T>(string key, T value)
    {
        _store[key] = Newtonsoft.Json.JsonConvert.SerializeObject(value);
        return Task.CompletedTask;
    }
}