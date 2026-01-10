// Frontend Performance Optimizations for Panda Cloud
// Add this script to your HTML for faster performance

(function() {
    'use strict';
    
    // Simple cache for API responses
    const cache = new Map();
    const CACHE_DURATION = 30000; // 30 seconds
    
    // Store original fetch function
    const originalFetch = window.fetch;
    
    // Enhanced fetch with caching for file listings
    window.fetch = function(url, options = {}) {
        // Only cache GET requests to /api/files
        if ((!options.method || options.method === 'GET') && url.includes('/api/files')) {
            const cacheKey = url + JSON.stringify(options.headers || {});
            const cached = cache.get(cacheKey);
            
            if (cached && (Date.now() - cached.timestamp) < CACHE_DURATION) {
                console.log('💾 Using cached response for:', url);
                return Promise.resolve(cached.response.clone());
            }
        }
        
        // Make the actual request
        const fetchPromise = originalFetch.call(this, url, options);
        
        // Cache successful file listing responses
        if ((!options.method || options.method === 'GET') && url.includes('/api/files')) {
            fetchPromise.then(response => {
                if (response.ok) {
                    const cacheKey = url + JSON.stringify(options.headers || {});
                    cache.set(cacheKey, {
                        response: response.clone(),
                        timestamp: Date.now()
                    });
                    
                    // Clean old cache entries
                    for (const [key, value] of cache.entries()) {
                        if (Date.now() - value.timestamp > CACHE_DURATION) {
                            cache.delete(key);
                        }
                    }
                }
            });
        }
        
        return fetchPromise;
    };
    
    // Clear cache when files are uploaded/deleted
    const originalRefresh = window.refresh;
    if (typeof originalRefresh === 'function') {
        window.refresh = function() {
            cache.clear();
            console.log('🗑️ Cleared cache for refresh');
            return originalRefresh.apply(this, arguments);
        };
    }
    
    // Performance monitoring
    let performanceLog = [];
    const logPerformance = (action, duration) => {
        performanceLog.push({action, duration, timestamp: Date.now()});
        if (performanceLog.length > 50) performanceLog = performanceLog.slice(-25);
        console.log(`⚡ ${action}: ${duration.toFixed(1)}ms`);
    };
    
    // Monitor API calls
    const observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
            if (entry.name.includes('/api/')) {
                logPerformance(`API ${entry.name.split('/').pop()}`, entry.duration);
            }
        }
    });
    observer.observe({entryTypes: ['measure', 'navigation']});
    
    // Expose performance data
    window.getPandaPerformance = () => ({
        cacheSize: cache.size,
        performanceLog: performanceLog.slice(-10),
        cacheKeys: Array.from(cache.keys())
    });
    
    console.log('🚀 Panda Cloud performance optimizations loaded');
    console.log('📊 Access performance data: getPandaPerformance()');
})();