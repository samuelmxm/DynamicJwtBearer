using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace PoweredSoft.DynamicJwtBearer.DynamicAuthority
{
    public class DynamicAuthorityJwtBearerHandlerConfigurationResolver : IDynamicJwtBearerHanderConfigurationResolver
    {
        private readonly IMemoryCache memoryCache;
        private readonly IDynamicJwtBearerAuthorityResolver dynamicJwtAuthorityResolver;
        private readonly HttpClient httpClient;

        public DynamicAuthorityJwtBearerHandlerConfigurationResolver(
            IMemoryCache memoryCache, IDynamicJwtBearerAuthorityResolver dynamicJwtAuthorityResolver, HttpClient httpClient)
        {
            this.memoryCache = memoryCache;
            this.dynamicJwtAuthorityResolver = dynamicJwtAuthorityResolver;
            this.httpClient = httpClient;
        }

        public async Task<OpenIdConnectConfiguration> ResolveCurrentOpenIdConfiguration(HttpContext context)
        {
            var authority = await dynamicJwtAuthorityResolver.ResolveAuthority(context);
            var cacheKey = $"DynamicAuthorityJwtBearerHandlerConfigurationResolver__{authority}";
            var ret = await memoryCache.GetOrCreateAsync(cacheKey, async cacheEntry =>
            {
                cacheEntry.AbsoluteExpirationRelativeToNow = dynamicJwtAuthorityResolver.ExpirationOfConfiguration;
                var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>
                ($"{authority}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(httpClient));
                
                var authorityConfiguration = await configurationManager.GetConfigurationAsync(context.RequestAborted);
                return authorityConfiguration;
            });

            return ret;
        }
    }
}
