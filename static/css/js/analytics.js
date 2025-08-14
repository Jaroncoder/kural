// static/js/analytics.js
async function fetchJSON(url) {
	const res = await fetch(url);
	if (!res.ok) throw new Error('Failed to fetch ' + url);
	return res.json();
}
document.addEventListener('DOMContentLoaded', async () => {
	try {
		const summary = await fetchJSON('/api/analytics/summary');
		const time = await fetchJSON('/api/analytics/time-series');
		const categories = await fetchJSON('/api/analytics/categories');
		const areas = await fetchJSON('/api/analytics/areas');

		const lineCtx = document.getElementById('lineChart');
		new Chart(lineCtx, {
			type: 'line',
			data: {
				labels: time.labels,
				datasets: [
					{ label: 'Reported', data: time.reported, borderColor: '#2d6cff', tension: .3 },
					{ label: 'Resolved', data: time.resolved, borderColor: '#00c896', tension: .3 }
				]
			},
			options: {
				plugins: { legend: { labels: { color: '#e8ecff' } } },
				scales: {
					x: { ticks: { color: '#9aa3c1' }, grid: { color: 'rgba(255,255,255,.06)' } },
					y: { ticks: { color: '#9aa3c1' }, grid: { color: 'rgba(255,255,255,.06)' } }
				}
			}
		});

		const pieCtx = document.getElementById('pieChart');
		new Chart(pieCtx, {
			type: 'pie',
			data: {
				labels: categories.labels,
				datasets: [{ data: categories.data, backgroundColor: ['#2d6cff','#00c896','#ffaa2b','#ff5d5d','#8a6bff','#33b1ff','#ff8ad6'] }]
			},
			options: { plugins: { legend: { labels: { color: '#e8ecff' } } } }
		});

		const barCtx = document.getElementById('barChart');
		new Chart(barCtx, {
			type: 'bar',
			data: {
				labels: areas.labels,
				datasets: [{ label: 'Issues', data: areas.data, backgroundColor: '#2d6cff' }]
			},
			options: {
				plugins: { legend: { labels: { color: '#e8ecff' } } },
				scales: {
					x: { ticks: { color: '#9aa3c1' }, grid: { display: false } },
					y: { ticks: { color: '#9aa3c1' }, grid: { color: 'rgba(255,255,255,.06)' } }
				}
			}
		});
	} catch (e) {
		console.error(e);
	}
});