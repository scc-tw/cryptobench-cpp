// Crypto-Bench Dashboard JavaScript
class CryptoBenchDashboard {
    constructor() {
        this.data = null;
        this.charts = {};
        this.supportedAlgorithms = this.initializeSupportedAlgorithms();
        this.initializePage();
    }

    initializeSupportedAlgorithms() {
        return {
            'Hash Functions': {
                'SHA-256': ['Crypto++', 'OpenSSL', 'Botan', 'libsodium', 'mbedTLS'],
                'SHA-512': ['Crypto++', 'OpenSSL', 'Botan', 'libsodium', 'mbedTLS'],
                'SHA3-256': ['Crypto++', 'OpenSSL', 'Botan', 'mbedTLS'], // libsodium doesn't support SHA3
                'BLAKE2b': ['Crypto++', 'OpenSSL', 'Botan', 'libsodium', 'mbedTLS']
            },
            'Symmetric Encryption': {
                'AES-128-GCM': ['Crypto++', 'OpenSSL', 'Botan', 'mbedTLS'], // libsodium only has AES-256-GCM
                'AES-256-GCM': ['Crypto++', 'OpenSSL', 'Botan', 'libsodium', 'mbedTLS'],
                'AES-256-CBC': ['Crypto++', 'OpenSSL', 'Botan', 'mbedTLS'], // libsodium doesn't support CBC
                'ChaCha20-Poly1305': ['Crypto++', 'OpenSSL', 'Botan', 'libsodium', 'mbedTLS']
            },
            'Asymmetric Cryptography': {
                'RSA-2048': ['Crypto++', 'Botan', 'mbedTLS'], // OpenSSL stubs not implemented
                'RSA-4096': ['Crypto++', 'Botan', 'mbedTLS'], // OpenSSL stubs not implemented
                'ECDSA-P256': ['Crypto++', 'Botan', 'mbedTLS'], // OpenSSL stubs not implemented
                'Ed25519': ['Crypto++', 'Botan', 'libsodium', 'mbedTLS'] // OpenSSL stubs not implemented
            },
            'Key Exchange': {
                'ECDH-P256': ['Crypto++', 'Botan', 'mbedTLS'], // OpenSSL stubs not implemented
                'X25519': ['Crypto++', 'Botan', 'libsodium', 'mbedTLS'] // OpenSSL stubs not implemented
            },
            'Message Authentication': {
                'HMAC-SHA256': ['Crypto++', 'OpenSSL', 'Botan', 'libsodium', 'mbedTLS'],
                'Poly1305': ['Crypto++', 'OpenSSL', 'Botan', 'libsodium', 'mbedTLS']
            }
        };
    }

    initializePage() {
        this.renderAlgorithmSupport();
        
        // Load URL from hash if present
        const hash = window.location.hash.substring(1);
        if (hash) {
            document.getElementById('jsonUrl').value = decodeURIComponent(hash);
            this.loadBenchmarkData();
        }
    }

    renderAlgorithmSupport() {
        const container = document.getElementById('algorithmSupport');
        const libraries = ['Crypto++', 'OpenSSL', 'Botan', 'libsodium', 'mbedTLS'];
        
        Object.entries(this.supportedAlgorithms).forEach(([category, algorithms]) => {
            const categoryDiv = document.createElement('div');
            categoryDiv.className = 'algorithm-category';
            
            const title = document.createElement('h3');
            title.textContent = category;
            categoryDiv.appendChild(title);
            
            const list = document.createElement('ul');
            list.className = 'algorithm-list';
            
            Object.entries(algorithms).forEach(([algorithm, supportedLibs]) => {
                const item = document.createElement('li');
                item.innerHTML = `<strong>${algorithm}</strong><br>`;
                
                libraries.forEach(lib => {
                    const span = document.createElement('span');
                    span.textContent = lib;
                    span.className = supportedLibs.includes(lib) ? 'supported' : 'not-supported';
                    item.appendChild(span);
                    if (lib !== libraries[libraries.length - 1]) {
                        item.appendChild(document.createTextNode(', '));
                    }
                });
                
                list.appendChild(item);
            });
            
            categoryDiv.appendChild(list);
            container.appendChild(categoryDiv);
        });
    }

    showLoading() {
        document.getElementById('loading').style.display = 'block';
        document.getElementById('error').style.display = 'none';
        document.getElementById('statsGrid').style.display = 'none';
        document.getElementById('chartsContainer').style.display = 'none';
    }

    hideLoading() {
        document.getElementById('loading').style.display = 'none';
    }

    showError(message) {
        const errorDiv = document.getElementById('error');
        errorDiv.innerHTML = `<strong>Error:</strong> ${message}`;
        errorDiv.style.display = 'block';
        this.hideLoading();
    }

    async loadBenchmarkData() {
        const url = document.getElementById('jsonUrl').value.trim();
        if (!url) {
            this.showError('Please enter a valid URL to benchmark results.');
            return;
        }

        // Update URL hash
        window.location.hash = encodeURIComponent(url);

        this.showLoading();

        try {
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            this.data = data;
            this.renderDashboard();
        } catch (error) {
            this.showError(`Failed to load benchmark data: ${error.message}`);
        }
    }

    loadSampleData() {
        // Generate sample data for demonstration
        this.data = this.generateSampleData();
        this.renderDashboard();
    }

    generateSampleData() {
        const libraries = ['Crypto++', 'OpenSSL', 'Botan', 'libsodium', 'mbedTLS'];
        const algorithms = ['SHA256', 'SHA512', 'AES256GCM', 'ChaCha20Poly1305', 'Ed25519'];
        const inputSizes = ['1024', '4096', '16384'];
        const configurations = [];

        libraries.forEach(lib => {
            [false, true].forEach(pgo => {
                const benchmarks = [];
                algorithms.forEach(algo => {
                    inputSizes.forEach(size => {
                        // Skip unsupported combinations
                        if (lib === 'libsodium' && algo === 'SHA3_256') return;
                        if (lib === 'OpenSSL' && ['Ed25519', 'X25519'].includes(algo)) return;

                        const basePerf = Math.random() * 2000000000; // Base performance
                        const pgoMultiplier = pgo ? 1.1 + Math.random() * 0.3 : 1.0; // PGO boost
                        
                        benchmarks.push({
                            name: `${lib}/${algo}/${size}`,
                            library: lib,
                            algorithm: algo,
                            input_size: size,
                            time_ns: Math.floor(1000000000 / (basePerf * pgoMultiplier / parseInt(size))),
                            bytes_per_second: Math.floor(basePerf * pgoMultiplier),
                            iterations: Math.floor(Math.random() * 100000) + 10000
                        });
                    });
                });

                configurations.push({
                    compiler: `${lib.toLowerCase()}-compiler`,
                    platform: 'ubuntu-latest',
                    pgo_enabled: pgo,
                    benchmark_count: benchmarks.length,
                    benchmarks: benchmarks
                });
            });
        });

        return {
            summary_metadata: {
                generated_at: new Date().toISOString(),
                total_configurations: configurations.length,
                workflow_run_id: 'sample-123',
                commit_sha: 'abc123def456',
                repository: 'user/crypto-bench'
            },
            configurations: configurations,
            performance_comparison: {
                fastest_by_algorithm: {},
                compiler_rankings: {},
                pgo_impact: {}
            }
        };
    }

    renderDashboard() {
        this.hideLoading();
        this.renderStats();
        this.renderCharts();
        document.getElementById('statsGrid').style.display = 'grid';
        document.getElementById('chartsContainer').style.display = 'block';
    }

    renderStats() {
        const statsGrid = document.getElementById('statsGrid');
        statsGrid.innerHTML = '';

        const totalBenchmarks = this.data.configurations.reduce((sum, config) => sum + config.benchmark_count, 0);
        const totalConfigurations = this.data.summary_metadata.total_configurations;
        const avgBenchmarksPerConfig = Math.round(totalBenchmarks / totalConfigurations);

        const stats = [
            { title: totalConfigurations.toString(), subtitle: 'Configurations Tested' },
            { title: totalBenchmarks.toString(), subtitle: 'Total Benchmarks' },
            { title: avgBenchmarksPerConfig.toString(), subtitle: 'Avg per Configuration' },
            { title: new Date(this.data.summary_metadata.generated_at).toLocaleDateString(), subtitle: 'Generated' }
        ];

        stats.forEach(stat => {
            const card = document.createElement('div');
            card.className = 'stat-card';
            card.innerHTML = `
                <h3>${stat.title}</h3>
                <p>${stat.subtitle}</p>
            `;
            statsGrid.appendChild(card);
        });
    }

    renderCharts() {
        const container = document.getElementById('chartsContainer');
        container.innerHTML = '';

        // Performance by Library Chart
        this.renderPerformanceByLibrary(container);
        
        // PGO Impact Chart
        this.renderPGOImpact(container);
        
        // Algorithm Performance Comparison
        this.renderAlgorithmComparison(container);
        
        // Throughput Heatmap
        this.renderThroughputHeatmap(container);
    }

    renderPerformanceByLibrary(container) {
        const chartCard = document.createElement('div');
        chartCard.className = 'chart-card';
        chartCard.innerHTML = `
            <h2>📈 Performance by Library (MB/s)</h2>
            <div class="chart-wrapper">
                <canvas id="performanceChart"></canvas>
            </div>
        `;
        container.appendChild(chartCard);

        // Aggregate performance data by library
        const libraryData = {};
        this.data.configurations.forEach(config => {
            config.benchmarks.forEach(bench => {
                const key = `${bench.library}${config.pgo_enabled ? ' (PGO)' : ''}`;
                if (!libraryData[key]) {
                    libraryData[key] = [];
                }
                libraryData[key].push(bench.bytes_per_second / (1024 * 1024)); // Convert to MB/s
            });
        });

        // Calculate averages
        const labels = Object.keys(libraryData);
        const data = labels.map(label => {
            const values = libraryData[label];
            return values.reduce((sum, val) => sum + val, 0) / values.length;
        });

        const ctx = document.getElementById('performanceChart').getContext('2d');
        this.charts.performance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Average Performance (MB/s)',
                    data: data,
                    backgroundColor: labels.map((_, i) => 
                        labels[i].includes('PGO') ? 'rgba(102, 126, 234, 0.8)' : 'rgba(102, 126, 234, 0.4)'
                    ),
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Performance (MB/s)'
                        }
                    }
                }
            }
        });
    }

    renderPGOImpact(container) {
        const chartCard = document.createElement('div');
        chartCard.className = 'chart-card';
        chartCard.innerHTML = `
            <h2>🚀 Profile-Guided Optimization Impact</h2>
            <div class="chart-wrapper">
                <canvas id="pgoChart"></canvas>
            </div>
        `;
        container.appendChild(chartCard);

        // Calculate PGO impact by library
        const pgoImpact = {};
        const libraries = [...new Set(this.data.configurations.map(c => c.benchmarks.map(b => b.library)).flat())];

        libraries.forEach(lib => {
            const noPgoData = [];
            const pgoData = [];

            this.data.configurations.forEach(config => {
                config.benchmarks.forEach(bench => {
                    if (bench.library === lib) {
                        if (config.pgo_enabled) {
                            pgoData.push(bench.bytes_per_second);
                        } else {
                            noPgoData.push(bench.bytes_per_second);
                        }
                    }
                });
            });

            if (noPgoData.length > 0 && pgoData.length > 0) {
                const avgNoPgo = noPgoData.reduce((sum, val) => sum + val, 0) / noPgoData.length;
                const avgPgo = pgoData.reduce((sum, val) => sum + val, 0) / pgoData.length;
                pgoImpact[lib] = ((avgPgo - avgNoPgo) / avgNoPgo) * 100;
            }
        });

        const labels = Object.keys(pgoImpact);
        const data = Object.values(pgoImpact);

        const ctx = document.getElementById('pgoChart').getContext('2d');
        this.charts.pgo = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'PGO Performance Improvement (%)',
                    data: data,
                    backgroundColor: data.map(val => 
                        val > 0 ? 'rgba(34, 197, 94, 0.8)' : 'rgba(239, 68, 68, 0.8)'
                    ),
                    borderColor: data.map(val => 
                        val > 0 ? 'rgba(34, 197, 94, 1)' : 'rgba(239, 68, 68, 1)'
                    ),
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        title: {
                            display: true,
                            text: 'Performance Improvement (%)'
                        }
                    }
                }
            }
        });
    }

    renderAlgorithmComparison(container) {
        const chartCard = document.createElement('div');
        chartCard.className = 'chart-card';
        chartCard.innerHTML = `
            <h2>🔐 Algorithm Performance Comparison</h2>
            <div class="chart-wrapper large">
                <canvas id="algorithmChart"></canvas>
            </div>
        `;
        container.appendChild(chartCard);

        // Get unique algorithms and libraries
        const algorithms = [...new Set(this.data.configurations.map(c => c.benchmarks.map(b => b.algorithm)).flat())];
        const libraries = [...new Set(this.data.configurations.map(c => c.benchmarks.map(b => b.library)).flat())];
        
        const colors = [
            'rgba(255, 99, 132, 0.8)',
            'rgba(54, 162, 235, 0.8)',
            'rgba(255, 205, 86, 0.8)',
            'rgba(75, 192, 192, 0.8)',
            'rgba(153, 102, 255, 0.8)'
        ];

        const datasets = libraries.map((lib, index) => {
            const data = algorithms.map(algo => {
                const benchmarks = [];
                this.data.configurations.forEach(config => {
                    config.benchmarks.forEach(bench => {
                        if (bench.library === lib && bench.algorithm === algo) {
                            benchmarks.push(bench.bytes_per_second);
                        }
                    });
                });
                
                if (benchmarks.length === 0) return 0;
                return benchmarks.reduce((sum, val) => sum + val, 0) / benchmarks.length / (1024 * 1024);
            });

            return {
                label: lib,
                data: data,
                backgroundColor: colors[index % colors.length],
                borderColor: colors[index % colors.length].replace('0.8', '1'),
                borderWidth: 2
            };
        });

        const ctx = document.getElementById('algorithmChart').getContext('2d');
        this.charts.algorithm = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: algorithms,
                datasets: datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Performance (MB/s)'
                        }
                    }
                }
            }
        });
    }

    renderThroughputHeatmap(container) {
        const chartCard = document.createElement('div');
        chartCard.className = 'chart-card';
        chartCard.innerHTML = `
            <h2>🔥 Throughput Heatmap by Input Size</h2>
            <div class="chart-wrapper large">
                <canvas id="heatmapChart"></canvas>
            </div>
        `;
        container.appendChild(chartCard);

        // Create scatter plot data for heatmap effect
        const scatterData = [];
        const libraries = [...new Set(this.data.configurations.map(c => c.benchmarks.map(b => b.library)).flat())];
        const colors = [
            'rgba(255, 99, 132, 0.6)',
            'rgba(54, 162, 235, 0.6)',
            'rgba(255, 205, 86, 0.6)',
            'rgba(75, 192, 192, 0.6)',
            'rgba(153, 102, 255, 0.6)'
        ];

        libraries.forEach((lib, libIndex) => {
            const points = [];
            this.data.configurations.forEach(config => {
                config.benchmarks.forEach(bench => {
                    if (bench.library === lib) {
                        points.push({
                            x: parseInt(bench.input_size),
                            y: bench.bytes_per_second / (1024 * 1024)
                        });
                    }
                });
            });

            scatterData.push({
                label: lib,
                data: points,
                backgroundColor: colors[libIndex % colors.length],
                borderColor: colors[libIndex % colors.length].replace('0.6', '1'),
                pointRadius: 6,
                pointHoverRadius: 8
            });
        });

        const ctx = document.getElementById('heatmapChart').getContext('2d');
        this.charts.heatmap = new Chart(ctx, {
            type: 'scatter',
            data: {
                datasets: scatterData
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top'
                    }
                },
                scales: {
                    x: {
                        type: 'logarithmic',
                        title: {
                            display: true,
                            text: 'Input Size (bytes)'
                        }
                    },
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Throughput (MB/s)'
                        }
                    }
                }
            }
        });
    }
}

// Global functions
function loadBenchmarkData() {
    window.dashboard.loadBenchmarkData();
}

function loadSampleData() {
    window.dashboard.loadSampleData();
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new CryptoBenchDashboard();
});
