describe('/metrics/', () => {
  describe('challenge "exposedMetricsChallenge"', () => {
    it('Challenge is solved on accessing the /metrics route as an administrator', () => {
      cy.login({ email: 'admin', password: 'admin123' })
      cy.window().then((window) => {
        const token = window.localStorage.getItem('token')
        cy.request({
          url: '/metrics',
          headers: { Authorization: `Bearer ${token}` }
        })
      })
      cy.expectChallengeSolved({ challenge: 'Exposed Metrics' })
    })
  })
})
